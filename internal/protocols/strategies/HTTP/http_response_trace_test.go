package HTTP

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/plugins"
	"github.com/stretchr/testify/require"
)

func TestHTTPResponseRecorded_Static401(t *testing.T) {
	tr := &mockTracer{}
	cmd := parser.Command{
		Regex: regexp.MustCompile(".*"), Handler: "Unauthorized", StatusCode: http.StatusUnauthorized,
	}
	rec := httptest.NewRecorder()
	newHTTPHandler(parser.BeelzebubServiceConfiguration{
		Description: "Apache 401", Commands: []parser.Command{cmd},
	}, tr).ServeHTTP(rec, httptest.NewRequest("GET", "/admin", nil))

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Equal(t, "Unauthorized", rec.Body.String())
	require.Len(t, tr.events, 1)
	require.Equal(t, "Unauthorized", tr.events[0].CommandOutput)
	require.Equal(t, "Apache 401", tr.events[0].Description)
}

func TestHTTPResponseRecorded_Fallback404(t *testing.T) {
	tr := &mockTracer{}
	conf := parser.BeelzebubServiceConfiguration{
		Commands:        []parser.Command{{Regex: regexp.MustCompile("^/known$"), Handler: "Known", StatusCode: 200}},
		FallbackCommand: parser.Command{Handler: "404 Not Found!", StatusCode: http.StatusNotFound},
	}
	rec := httptest.NewRecorder()
	newHTTPHandler(conf, tr).ServeHTTP(rec, httptest.NewRequest("GET", "/unknown", nil))

	require.Equal(t, http.StatusNotFound, rec.Code)
	require.Equal(t, "404 Not Found!", rec.Body.String())
	require.Len(t, tr.events, 1)
	require.Equal(t, rec.Body.String(), tr.events[0].CommandOutput)
}

func TestHTTPResponseRecorded_MethodNotAllowed(t *testing.T) {
	tr := &mockTracer{}
	conf := parser.BeelzebubServiceConfiguration{
		Commands: []parser.Command{{
			Regex: regexp.MustCompile("^/submit$"), Methods: []string{http.MethodPost},
			Handler: "submitted", StatusCode: http.StatusOK,
		}},
	}
	rec := httptest.NewRecorder()
	newHTTPHandler(conf, tr).ServeHTTP(rec, httptest.NewRequest("GET", "/submit", nil))

	require.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	require.Len(t, tr.events, 1)
	require.Equal(t, http.StatusText(http.StatusMethodNotAllowed), tr.events[0].CommandOutput)
}

func TestHTTPResponseRecorded_PreservesRequestBody(t *testing.T) {
	tr := &mockTracer{}
	conf := parser.BeelzebubServiceConfiguration{
		Commands: []parser.Command{{
			Regex: regexp.MustCompile(".*"), Handler: "accepted", StatusCode: http.StatusAccepted,
		}},
	}
	rec := httptest.NewRecorder()
	newHTTPHandler(conf, tr).ServeHTTP(rec, httptest.NewRequest("POST", "/submit", strings.NewReader("sample input")))

	require.Len(t, tr.events, 1)
	require.Equal(t, "sample input", tr.events[0].Body)
	require.Equal(t, "accepted", tr.events[0].CommandOutput)
}

func TestHTTPResponseRecorded_UnicodeOutputTruncatedSafely(t *testing.T) {
	tr := &mockTracer{}
	response := strings.Repeat("🚀", 520)
	conf := parser.BeelzebubServiceConfiguration{
		Commands: []parser.Command{{Regex: regexp.MustCompile(".*"), Handler: response, StatusCode: 200}},
	}
	rec := httptest.NewRecorder()
	newHTTPHandler(conf, tr).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	require.Equal(t, response, rec.Body.String())
	require.Len(t, tr.events, 1)
	require.True(t, utf8.ValidString(tr.events[0].CommandOutput))
	require.Equal(t, 500, utf8.RuneCountInString(tr.events[0].CommandOutput))
	require.Equal(t, strings.Repeat("🚀", 500), tr.events[0].CommandOutput)
}

func TestHTTPResponseRecorded_HTTPPluginBody(t *testing.T) {
	tr := &mockTracer{}
	conf := parser.BeelzebubServiceConfiguration{ServerName: "TestServer", ServerVersion: "1.0"}
	resp, err := buildHTTPResponse(conf, tr, parser.Command{Plugin: plugins.MazePluginName}, httptest.NewRequest("GET", "/maze", nil))
	require.NoError(t, err)
	require.Len(t, tr.events, 1)
	want := []rune(resp.Body)
	if len(want) > 500 {
		want = want[:500]
	}
	require.Equal(t, string(want), tr.events[0].CommandOutput)
}
