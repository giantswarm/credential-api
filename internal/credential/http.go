package credential

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func respond(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func respondError(writer http.ResponseWriter, err error) {
	status := http.StatusServiceUnavailable
	switch err {
	case errInvalid, errMode:
		status = http.StatusBadRequest
	case errOwner, errForbidden:
		status = http.StatusForbidden
	case errNotFound:
		status = http.StatusNotFound
	case errConflict, errUncertain:
		status = http.StatusConflict
	default:
		err = errUnavailable
	}
	message := err.Error()
	if err == errForbidden {
		message = "Ask an admin: an admin must start setup with their own sign-in"
	}
	respond(writer, status, map[string]string{"error": message})
}

func decode(writer http.ResponseWriter, request *http.Request, target any, limit int64) bool {
	if !jsonContent(request) {
		respondError(writer, errInvalid)
		return false
	}
	request.Body = http.MaxBytesReader(writer, request.Body, limit)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		respondError(writer, errInvalid)
		return false
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		respondError(writer, errInvalid)
		return false
	}
	return true
}

func (b *Browser) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, request *http.Request) { writer.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("POST /v1/operations", func(writer http.ResponseWriter, request *http.Request) {
		manager, err := b.service.AuthenticateManager(request.Context(), strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer "))
		if err != nil {
			respondError(writer, err)
			return
		}
		var creation Create
		if !decode(writer, request, &creation, 128*1024) {
			return
		}
		status, err := b.service.Open(request.Context(), manager, creation)
		if err != nil {
			respondError(writer, err)
			return
		}
		respond(writer, http.StatusCreated, status)
	})
	mux.HandleFunc("GET /v1/operations/{id}", func(writer http.ResponseWriter, request *http.Request) {
		manager, err := b.service.AuthenticateManager(request.Context(), strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer "))
		if err != nil {
			respondError(writer, err)
			return
		}
		status, err := b.service.ManagerStatus(request.Context(), manager, request.PathValue("id"))
		if err != nil {
			respondError(writer, err)
			return
		}
		respond(writer, http.StatusOK, status)
	})
	mux.HandleFunc("GET "+browserPrefix+"/signin", func(writer http.ResponseWriter, request *http.Request) {
		origin, _ := b.origin(request)
		b.signIn(writer, request, origin)
	})
	mux.HandleFunc("GET "+browserPrefix+"/callback", func(writer http.ResponseWriter, request *http.Request) {
		origin, _ := b.origin(request)
		b.callback(writer, request, origin)
	})
	mux.HandleFunc("GET /credentials/{id}", func(writer http.ResponseWriter, request *http.Request) {
		origin, _ := b.origin(request)
		if _, err := b.session(request, origin); err != nil {
			writer.Header().Set("Location", browserPrefix+"/signin?"+url.Values{operationKey: {request.PathValue("id")}}.Encode())
			writer.WriteHeader(http.StatusSeeOther)
			return
		}
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(writer, page)
	})
	mux.HandleFunc("GET "+browserPrefix+"/app.js", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/javascript")
		_, _ = io.WriteString(writer, script)
	})
	mux.HandleFunc("GET "+browserPrefix+"/api/operations/{id}", func(writer http.ResponseWriter, request *http.Request) {
		origin, _ := b.origin(request)
		session, err := b.session(request, origin)
		if err != nil {
			respondError(writer, err)
			return
		}
		confirmation, err := b.service.Confirm(request.Context(), session.Person, session.Token, request.PathValue("id"))
		if err != nil {
			respondError(writer, err)
			return
		}
		respond(writer, http.StatusOK, map[string]any{"operation": confirmation, "csrf": session.CSRF})
	})
	for _, action := range []string{"save", "cancel"} {
		mux.HandleFunc("POST "+browserPrefix+"/api/operations/{id}/"+action, func(writer http.ResponseWriter, request *http.Request) {
			origin, _ := b.origin(request)
			session, err := b.session(request, origin)
			if err != nil || !validWrite(request, session, origin) {
				respondError(writer, errOwner)
				return
			}
			if action == "cancel" {
				var cancellation struct {
					Version string `json:"version"`
				}
				if !decode(writer, request, &cancellation, 4096) {
					return
				}
				if err := b.service.Cancel(request.Context(), session.Person, request.PathValue("id"), cancellation.Version); err != nil {
					respondError(writer, err)
					return
				}
				respond(writer, http.StatusOK, map[string]string{"state": cancelled})
				return
			}
			var save Save
			if !decode(writer, request, &save, 2<<20) {
				return
			}
			status, err := b.service.Save(request.Context(), session.Person, session.Token, request.PathValue("id"), save)
			if err != nil {
				respondError(writer, err)
				return
			}
			respond(writer, http.StatusOK, status)
		})
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store, max-age=0")
		writer.Header().Set("Pragma", "no-cache")
		writer.Header().Set("X-Frame-Options", "DENY")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if request.URL.Path != "/healthz" {
			if _, ok := b.origin(request); !ok {
				respondError(writer, errInvalid)
				return
			}
		}
		mux.ServeHTTP(writer, request)
	})
}
