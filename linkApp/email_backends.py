import ssl
import smtplib
import logging
from django.core.mail.backends.smtp import EmailBackend

logger = logging.getLogger(__name__)

class SSLEmailBackend(EmailBackend):
    def open(self):
        if self.connection:
            return False

        try:
            self.connection = smtplib.SMTP(self.host, self.port, timeout=15)
            self.connection.ehlo()

            if self.use_tls:
                context = ssl.create_default_context()
                self.connection.starttls(context=context)
                self.connection.ehlo()

            if self.username and self.password:
                self.connection.login(self.username, self.password)

            return True

        except Exception as exc:
            logger.exception("SMTP connection failed: %s", exc)
            if not self.fail_silently:
                raise
            return False