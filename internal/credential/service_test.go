package credential

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

func TestAuthenticateManagerReviewsVerifiedSubject(t *testing.T) {
	claims, err := json.Marshal(map[string]int64{"iat": time.Now().Unix(), "exp": time.Now().Add(10 * time.Minute).Unix()})
	require.NoError(t, err)
	token := "synthetic." + base64.RawURLEncoding.EncodeToString(claims) + ".signature"
	subject := authenticationv1.UserInfo{
		Username: managerIdentity, UID: "manager-uid", Groups: []string{"system:serviceaccounts", "system:authenticated"},
		Extra: map[string]authenticationv1.ExtraValue{"authentication.kubernetes.io/pod-name": {"model-manager"}},
	}
	for _, test := range []struct {
		name        string
		status      authorizationv1.SubjectAccessReviewStatus
		reviewError error
		allowed     bool
	}{
		{name: "allowed", status: authorizationv1.SubjectAccessReviewStatus{Allowed: true}, allowed: true},
		{name: "denied", status: authorizationv1.SubjectAccessReviewStatus{Denied: true}},
		{name: "no decision"},
		{name: "contradictory", status: authorizationv1.SubjectAccessReviewStatus{Allowed: true, Denied: true}},
		{name: "evaluation error", status: authorizationv1.SubjectAccessReviewStatus{Allowed: true, EvaluationError: "unavailable"}},
		{name: "API error", reviewError: apierrors.NewServiceUnavailable("authorization unavailable")},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := fake.NewClientset()
			client.PrependReactor("create", "tokenreviews", func(action clienttesting.Action) (bool, runtime.Object, error) {
				review := action.(clienttesting.CreateAction).GetObject().(*authenticationv1.TokenReview)
				require.Equal(t, token, review.Spec.Token)
				require.Equal(t, []string{"credential-api"}, review.Spec.Audiences)
				return true, &authenticationv1.TokenReview{Status: authenticationv1.TokenReviewStatus{Authenticated: true, Audiences: review.Spec.Audiences, User: subject}}, nil
			})
			reviews := 0
			client.PrependReactor("create", "subjectaccessreviews", func(action clienttesting.Action) (bool, runtime.Object, error) {
				reviews++
				review := action.(clienttesting.CreateAction).GetObject().(*authorizationv1.SubjectAccessReview)
				require.Equal(t, subject.Username, review.Spec.User)
				require.Equal(t, subject.UID, review.Spec.UID)
				require.Equal(t, subject.Groups, review.Spec.Groups)
				require.Equal(t, authorizationv1.ExtraValue{"model-manager"}, review.Spec.Extra["authentication.kubernetes.io/pod-name"])
				require.Equal(t, &authorizationv1.ResourceAttributes{Namespace: "credentials", Verb: "create", Group: "credential.giantswarm.io", Version: "v1", Resource: "operations"}, review.Spec.ResourceAttributes)
				return true, &authorizationv1.SubjectAccessReview{Status: test.status}, test.reviewError
			})
			service := &Service{admin: client, configuration: Config{Audience: "credential-api", Namespace: "credentials", Managers: map[string][]string{managerIdentity: {"tenant-credential-model-"}}}}
			manager, err := service.AuthenticateManager(t.Context(), token)
			if test.allowed {
				require.NoError(t, err)
				require.Equal(t, managerIdentity, manager)
			} else {
				require.ErrorIs(t, err, errForbidden)
				require.Empty(t, manager)
			}
			require.Equal(t, 1, reviews)
		})
	}
}
