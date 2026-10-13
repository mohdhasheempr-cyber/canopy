import { useEffect, useState } from "react";
import Link from "next/link";
import { Button, Card, Container, Spinner } from "react-bootstrap";
import { Google as GoogleIcon } from "react-bootstrap-icons";
import { clearGoogleSessionToken, googleLoginURL, resolveGoogleUser } from "@/components/api";
import { WalletLogoIcon } from "@/components/svg_icons";

// Login() returns the login page with the 'Sign in with Google' option
export default function Login() {
  const [state, setState] = useState({
    loading: true,
    user: null,
  });

  // resolve the persisted session on mount
  useEffect(() => {
    resolveGoogleUser().then((user) => {
      setState({ loading: false, user: user });
    });
  }, []);

  // onSignOut() forgets the session and returns to the signed out view
  function onSignOut() {
    clearGoogleSessionToken();
    setState({ loading: false, user: null });
  }

  return (
    <Container id="login-container" className="d-flex align-items-center justify-content-center min-vh-100">
      <Card id="login-card" style={{ width: "26rem" }} className="text-center p-4">
        <Card.Body>
          <WalletLogoIcon className="nav-bar-logo mb-3" />
          <Card.Title id="login-title">Canopy Wallet</Card.Title>
          {state.loading ? (
            <Spinner id="spinner" animation="border" />
          ) : state.user ? (
            <>
              <Card.Text id="login-user" className="mb-1">
                Signed in as <strong>{state.user.email || state.user.name}</strong>
              </Card.Text>
              <Card.Text className="text-muted mb-4">Google account</Card.Text>
              <Link href="/" passHref legacyBehavior>
                <Button id="login-go-wallet" variant="primary" className="w-100 mb-2">
                  Go to Wallet
                </Button>
              </Link>
              <Button id="login-sign-out" variant="outline-secondary" className="w-100" onClick={onSignOut}>
                Sign out
              </Button>
            </>
          ) : (
            <>
              <Card.Text id="login-description" className="text-muted mb-4">
                Sign in to access your wallet
              </Card.Text>
              <Button
                id="login-google"
                variant="outline-dark"
                className="w-100 d-inline-flex align-items-center justify-content-center gap-2"
                onClick={() => {
                  window.location.assign(googleLoginURL());
                }}
              >
                <GoogleIcon size={20} />
                Sign in with Google
              </Button>
            </>
          )}
        </Card.Body>
      </Card>
    </Container>
  );
}
