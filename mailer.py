"""Sends email over SMTP. With no SMTP_HOST set, it prints messages to the server log instead."""
import logging, os, smtplib, ssl, threading
from email.message import EmailMessage

log = logging.getLogger("mailer")


def configured():
    return bool(os.getenv("SMTP_HOST"))


def send(to, subject, body):
    if not configured():
        print(f"\n=== EMAIL (SMTP not configured) ===\nTo: {to}\nSubject: {subject}\n\n{body}\n===================================\n", flush=True)
        return
    threading.Thread(target=_send, args=(to, subject, body), daemon=True).start()


def _send(to, subject, body):
    user, pw = os.getenv("SMTP_USER", ""), os.getenv("SMTP_PASSWORD", "")
    msg = EmailMessage()
    msg["From"] = os.getenv("SMTP_FROM") or user
    msg["To"], msg["Subject"] = to, subject
    msg.set_content(body)
    host, port = os.environ["SMTP_HOST"], int(os.getenv("SMTP_PORT", "587"))
    mode = os.getenv("SMTP_SECURITY", "starttls").lower()      # starttls | ssl | none
    try:
        ctx = ssl.create_default_context()
        s = smtplib.SMTP_SSL(host, port, timeout=20, context=ctx) if mode == "ssl" else smtplib.SMTP(host, port, timeout=20)
        with s:
            if mode == "starttls":
                s.starttls(context=ctx)
            if user:
                s.login(user, pw)
            s.send_message(msg)
    except Exception:
        log.exception("Could not send email to %s", to)
