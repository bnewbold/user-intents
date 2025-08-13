package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"

	_ "github.com/joho/godotenv/autoload"

	"github.com/bluesky-social/indigo/atproto/auth/oauth"
	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/syntax"

	"github.com/gorilla/sessions"
	"github.com/urfave/cli/v2"
)

func main() {
	app := cli.App{
		Name:   "oauth-web-demo",
		Usage:  "atproto OAuth web server demo",
		Action: runServer,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "session-secret",
				Usage:    "random string/token used for session cookie security",
				Required: true,
				EnvVars:  []string{"SESSION_SECRET"},
			},
			&cli.StringFlag{
				Name:    "hostname",
				Usage:   "public host name for this client (if not localhost dev mode)",
				EnvVars: []string{"CLIENT_HOSTNAME"},
			},
		},
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(h))
	app.RunAndExitOnError()
}

type Server struct {
	CookieStore *sessions.CookieStore
	Dir         identity.Directory
	OAuth       *oauth.ClientApp
}

//go:embed "base.html"
var tmplBaseText string

//go:embed "home.html"
var tmplHomeText string
var tmplHome = template.Must(template.Must(template.New("home.html").Parse(tmplBaseText)).Parse(tmplHomeText))

//go:embed "login.html"
var tmplLoginText string
var tmplLogin = template.Must(template.Must(template.New("login.html").Parse(tmplBaseText)).Parse(tmplLoginText))

//go:embed "intents.html"
var tmplIntentsText string
var tmplIntents = template.Must(template.Must(template.New("intents.html").Parse(tmplBaseText)).Parse(tmplIntentsText))

type WebInfo struct {
	DID string
	//Handle string
	Declaration *Declaration
}

func runServer(cctx *cli.Context) error {

	scopes := []string{"atproto", "transition:generic"}
	bind := ":8080"

	// TODO: localhost dev mode if hostname is empty
	var config oauth.ClientConfig
	hostname := cctx.String("hostname")
	if hostname == "" {
		config = oauth.NewLocalhostConfig(
			fmt.Sprintf("http://127.0.0.1%s/oauth/callback", bind),
			scopes,
		)
		slog.Info("configuring localhost OAuth client", "CallbackURL", config.CallbackURL)
	} else {
		config = oauth.NewPublicConfig(
			fmt.Sprintf("https://%s/oauth/client-metadata.json", hostname),
			fmt.Sprintf("https://%s/oauth/callback", hostname),
			scopes,
		)
	}

	oauthClient := oauth.NewClientApp(&config, oauth.NewMemStore())

	srv := Server{
		CookieStore: sessions.NewCookieStore([]byte(cctx.String("session-secret"))),
		Dir:         identity.DefaultDirectory(),
		OAuth:       oauthClient,
	}

	http.HandleFunc("GET /", srv.Homepage)
	http.HandleFunc("GET /oauth/client-metadata.json", srv.ClientMetadata)
	http.HandleFunc("GET /oauth/jwks.json", srv.JWKS)
	http.HandleFunc("GET /oauth/login", srv.OAuthLogin)
	http.HandleFunc("POST /oauth/login", srv.OAuthLogin)
	http.HandleFunc("GET /oauth/callback", srv.OAuthCallback)
	http.HandleFunc("GET /oauth/logout", srv.OAuthLogout)
	http.HandleFunc("GET /intents", srv.UpdateIntents)
	http.HandleFunc("POST /intents", srv.UpdateIntents)

	slog.Info("starting http server", "bind", bind)
	if err := http.ListenAndServe(bind, nil); err != nil {
		slog.Error("http shutdown", "err", err)
	}
	return nil
}

func (s *Server) currentSessionDID(r *http.Request) (*syntax.DID, string) {
	sess, _ := s.CookieStore.Get(r, "oauth-demo")
	accountDID, ok := sess.Values["account_did"].(string)
	if !ok || accountDID == "" {
		return nil, ""
	}
	did, err := syntax.ParseDID(accountDID)
	if err != nil {
		return nil, ""
	}
	sessionID, ok := sess.Values["session_id"].(string)
	if !ok || sessionID == "" {
		return nil, ""
	}

	return &did, sessionID
}

func strPtr(raw string) *string {
	return &raw
}

func (s *Server) ClientMetadata(w http.ResponseWriter, r *http.Request) {
	slog.Info("client metadata request", "url", r.URL, "host", r.Host)

	meta := s.OAuth.Config.ClientMetadata()
	meta.ClientName = strPtr("AI-PREF / Bluesky Demo App")
	meta.ClientURI = strPtr(fmt.Sprintf("https://%s", r.Host))

	// internal consistency check
	if err := meta.Validate(s.OAuth.Config.ClientID); err != nil {
		slog.Error("validating client metadata", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(meta); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s *Server) JWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	body := s.OAuth.Config.PublicJWKS()
	if err := json.NewEncoder(w).Encode(body); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s *Server) Homepage(w http.ResponseWriter, r *http.Request) {
	did, _ := s.currentSessionDID(r)
	if did != nil {
		tmplHome.Execute(w, WebInfo{DID: did.String()})
		return
	}
	tmplHome.Execute(w, nil)
}

func (s *Server) OAuthLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method != "POST" {
		tmplLogin.Execute(w, nil)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, fmt.Errorf("parsing form data: %w", err).Error(), http.StatusBadRequest)
		return
	}

	username := r.PostFormValue("username")

	slog.Info("OAuthLogin", "client_id", s.OAuth.Config.ClientID, "callback_url", s.OAuth.Config.CallbackURL)

	redirectURL, err := s.OAuth.StartAuthFlow(ctx, username)
	if err != nil {
		http.Error(w, fmt.Errorf("OAuth login failed: %w", err).Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
	return
}

func (s *Server) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	params := r.URL.Query()
	slog.Info("received callback", "params", params)

	sessData, err := s.OAuth.ProcessCallback(ctx, r.URL.Query())
	if err != nil {
		http.Error(w, fmt.Errorf("processing OAuth callback: %w", err).Error(), http.StatusBadRequest)
		return
	}

	// create signed cookie session, indicating account DID
	sess, _ := s.CookieStore.Get(r, "oauth-demo")
	sess.Values["account_did"] = sessData.AccountDID.String()
	sess.Values["session_id"] = sessData.SessionID
	if err := sess.Save(r, w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	slog.Info("login successful", "did", sessData.AccountDID.String())
	http.Redirect(w, r, "/intents", http.StatusFound)
}

func (s *Server) OAuthLogout(w http.ResponseWriter, r *http.Request) {

	// delete session from auth store
	did, sessionID := s.currentSessionDID(r)
	if did != nil {
		if err := s.OAuth.Store.DeleteSession(r.Context(), *did, sessionID); err != nil {
			slog.Error("failed to delete session", "did", did, "err", err)
		}
	}

	// wipe all secure cookie session data
	sess, _ := s.CookieStore.Get(r, "oauth-demo")
	sess.Values = make(map[any]any)
	err := sess.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	slog.Info("logged out")
	http.Redirect(w, r, "/", http.StatusFound)
}

func parseTriState(raw string) *bool {
	switch raw {
	case "allow":
		v := true
		return &v
	case "disallow":
		v := false
		return &v
	default:
		return nil
	}
}

func (s *Server) UpdateIntents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	did, sessionID := s.currentSessionDID(r)
	if did == nil {
		// TODO: suppowed to set a WWW header; and could redirect?
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	oauthSess, err := s.OAuth.ResumeSession(ctx, *did, sessionID)
	if err != nil {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	c := oauthSess.APIClient()
	info := WebInfo{
		DID: did.String(),
	}

	p := map[string]any{
		"repo":       did.String(),
		"collection": "org.user-intents.demo.declaration",
		"rkey":       "self",
	}
	resp := GetDeclarationResp{}
	err = c.Get(ctx, "com.atproto.repo.getRecord", p, &resp)
	if err != nil {
		slog.Info("could not fetch existing declaration", "err", err)
	}

	if r.Method != "POST" {
		info.Declaration = &resp.Value
		tmplIntents.Execute(w, info)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, fmt.Errorf("parsing form data: %w", err).Error(), http.StatusBadRequest)
		return
	}

	// TODO: have this not clobber current timestamps
	now := syntax.DatetimeNow().String()
	decl := Declaration{
		Type:      "org.user-intents.demo.declaration",
		UpdatedAt: now,
		SyntheticContentGeneration: &DeclarationIntent{
			Allow:     parseTriState(r.PostFormValue("syntheticContentGeneration")),
			UpdatedAt: now,
		},
		PublicAccessArchive: &DeclarationIntent{
			Allow:     parseTriState(r.PostFormValue("publicAccessArchive")),
			UpdatedAt: now,
		},
		BulkDataset: &DeclarationIntent{
			Allow:     parseTriState(r.PostFormValue("bulkDataset")),
			UpdatedAt: now,
		},
		ProtocolBridging: &DeclarationIntent{
			Allow:     parseTriState(r.PostFormValue("protocolBridging")),
			UpdatedAt: now,
		},
	}

	//nope := false
	body := PutDeclarationBody{
		Repo:       did.String(),
		Collection: "org.user-intents.demo.declaration",
		Rkey:       "self",
		Record:     decl,
	}

	slog.Info("updating intents", "did", did, "declaration", decl)
	if err := c.Post(ctx, "com.atproto.repo.putRecord", body, nil); err != nil {
		slog.Info("failed to update intents record", "err", err)
		http.Error(w, fmt.Errorf("update failed: %w", err).Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}
