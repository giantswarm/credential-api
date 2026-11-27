package credential

import (
	"context"
	"encoding/json"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	typedcore "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/util/retry"
)

// Store holds metadata only. Resource versions serialize transitions across replicas.
type Store struct {
	maps     typedcore.ConfigMapInterface
	capacity int64
}

func (s *Store) read(ctx context.Context, id string) (*Operation, error) {
	if len(id) != 48 {
		return nil, errNotFound
	}
	for _, letter := range id {
		if (letter < 'a' || letter > 'f') && (letter < '0' || letter > '9') {
			return nil, errNotFound
		}
	}
	item, err := s.maps.Get(ctx, "credential-"+id, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, errUnavailable
	}
	var operation Operation
	if json.Unmarshal([]byte(item.Data[operationKey]), &operation) != nil || operation.ID != id || item.Labels[operationLabel] != labelEnabled {
		return nil, errUnavailable
	}
	operation.Version = item.ResourceVersion
	return &operation, nil
}

func (s *Store) put(ctx context.Context, operation *Operation) error {
	body, err := json.Marshal(operation)
	if err != nil || len(body) > 128*1024 {
		return errInvalid
	}
	item := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "credential-" + operation.ID, ResourceVersion: operation.Version, Labels: map[string]string{operationLabel: labelEnabled}}, Data: map[string]string{operationKey: string(body)}}
	if operation.Version == "" {
		item, err = s.maps.Create(ctx, item, metav1.CreateOptions{})
	} else {
		item, err = s.maps.Update(ctx, item, metav1.UpdateOptions{})
	}
	if apierrors.IsAlreadyExists(err) || apierrors.IsConflict(err) {
		return errConflict
	}
	if err != nil {
		return errUnavailable
	}
	operation.Version = item.ResourceVersion
	return nil
}

func (s *Store) prepare(ctx context.Context, operation *Operation) (*Operation, error) {
	previous, err := s.read(ctx, operation.ID)
	if err == nil {
		if previous.Manager != operation.Manager || digest(previous.Create) != digest(operation.Create) {
			return nil, errConflict
		}
		if time.Now().Before(previous.ExpiresAt) {
			return previous, nil
		}
		operation.Version = previous.Version
	} else if err != errNotFound {
		return nil, err
	}
	if err := s.reserve(ctx, operation); err != nil {
		return nil, err
	}
	items, err := s.maps.List(ctx, metav1.ListOptions{LabelSelector: operationLabel + "=true", Limit: s.capacity + 1})
	if err != nil {
		return nil, errUnavailable
	}
	active := int64(0)
	for _, item := range items.Items {
		if item.Name == "credential-"+operation.ID {
			continue
		}
		var existing Operation
		if json.Unmarshal([]byte(item.Data[operationKey]), &existing) != nil || time.Now().Before(existing.ExpiresAt) {
			active++
			continue
		}
		version := item.ResourceVersion
		_ = s.maps.Delete(ctx, item.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{ResourceVersion: &version}})
	}
	if active >= s.capacity || items.Continue != "" {
		return nil, errConflict
	}
	if err := s.put(ctx, operation); err != nil {
		if err == errConflict {
			stored, err := s.read(ctx, operation.ID)
			if err != nil {
				return nil, err
			}
			if stored.Manager != operation.Manager || digest(stored.Create) != digest(operation.Create) {
				return nil, errConflict
			}
			return stored, nil
		}
		return nil, err
	}
	return operation, nil
}

func (s *Store) reserve(ctx context.Context, operation *Operation) error {
	err := retry.OnError(retry.DefaultRetry, func(err error) bool { return apierrors.IsConflict(err) || apierrors.IsAlreadyExists(err) }, func() error {
		item, err := s.maps.Get(ctx, "credential-capacity", metav1.GetOptions{})
		fresh := apierrors.IsNotFound(err)
		if err != nil && !fresh {
			return errUnavailable
		}
		reservations := map[string]time.Time{}
		if fresh {
			item = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "credential-capacity"}}
		} else if json.Unmarshal([]byte(item.Data["reservations"]), &reservations) != nil {
			return errUnavailable
		}
		for id, expires := range reservations {
			if !time.Now().Before(expires) {
				delete(reservations, id)
			}
		}
		if _, held := reservations[operation.ID]; !held && int64(len(reservations)) >= s.capacity {
			return errConflict
		}
		reservations[operation.ID] = operation.ExpiresAt
		body, _ := json.Marshal(reservations)
		item.Data = map[string]string{"reservations": string(body)}
		if fresh {
			_, err = s.maps.Create(ctx, item, metav1.CreateOptions{})
		} else {
			_, err = s.maps.Update(ctx, item, metav1.UpdateOptions{})
		}
		return err
	})
	if err == errConflict {
		return errConflict
	}
	if err != nil {
		return errUnavailable
	}
	return nil
}

func (s *Store) Expire(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			items, err := s.maps.List(ctx, metav1.ListOptions{LabelSelector: operationLabel + "=true"})
			if err != nil {
				continue
			}
			for _, item := range items.Items {
				var operation Operation
				if json.Unmarshal([]byte(item.Data[operationKey]), &operation) != nil || time.Now().Before(operation.ExpiresAt) {
					continue
				}
				version := item.ResourceVersion
				_ = s.maps.Delete(ctx, item.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{ResourceVersion: &version}})
			}
		}
	}
}
