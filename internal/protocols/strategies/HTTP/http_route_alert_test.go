package HTTP

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/stretchr/testify/require"
)

func TestStaticRouteAlertTrace(t *testing.T) {
	conf := parser.BeelzebubServiceConfiguration{
		Description: "static-route-honeypot",
		Commands: []parser.Command{{
			Regex:      regexp.MustCompile(`^/known$`),
			Handler:    "fake static content",
			StatusCode: http.StatusOK,
		}},
	}
	tracer := &mockTracer{}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/known", nil)
	request.RemoteAddr = "203.0.113.7:54321"

	newHTTPHandler(conf, tracer).ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	require.Equal(t, "fake static content", response.Body.String())
	require.Len(t, tracer.events, 1)
	require.Equal(t, "HTTP", tracer.events[0].Protocol)
	require.Equal(t, "/known", tracer.events[0].RequestURI)
	require.Equal(t, "203.0.113.7", tracer.events[0].SourceIp)
	require.Equal(t, "fake static content", tracer.events[0].CommandOutput)
}

func TestFallbackRouteAlertTrace(t *testing.T) {
	conf := parser.BeelzebubServiceConfiguration{
		Description: "static-route-honeypot",
		FallbackCommand: parser.Command{
			Handler:    "fake fallback content",
			StatusCode: http.StatusNotFound,
		},
	}
	tracer := &mockTracer{}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/unknown", nil)

	newHTTPHandler(conf, tracer).ServeHTTP(response, request)

	require.Equal(t, http.StatusNotFound, response.Code)
	require.Len(t, tracer.events, 1)
	require.Equal(t, "/unknown", tracer.events[0].RequestURI)
	require.Equal(t, "fake fallback content", tracer.events[0].CommandOutput)
}

func TestUnmatchedRouteWithoutFallbackStillTraced(t *testing.T) {
	conf := parser.BeelzebubServiceConfiguration{
		Description: "static-route-honeypot",
		Commands: []parser.Command{{
			Regex:      regexp.MustCompile(`^/known$`),
			Handler:    "fake static content",
			StatusCode: http.StatusOK,
		}},
	}
	tracer := &mockTracer{}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/not-configured", nil)
	request.RemoteAddr = "203.0.113.8:54322"

	newHTTPHandler(conf, tracer).ServeHTTP(response, request)

	require.Len(t, tracer.events, 1, "unknown paths must generate a log event")
	require.Equal(t, "HTTP", tracer.events[0].Protocol)
	require.Equal(t, "/not-configured", tracer.events[0].RequestURI)
	require.Equal(t, "203.0.113.8", tracer.events[0].SourceIp)
	require.Equal(t, "static-route-honeypot", tracer.events[0].Description)
}
