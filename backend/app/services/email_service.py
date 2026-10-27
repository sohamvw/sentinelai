import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from app.core.config import settings

logger = logging.getLogger(__name__)

class EmailService:
    @staticmethod
    def send_verification_email(recipient_email: str, first_name: str, otp_code: str) -> bool:
        """
        Sends 6-digit OTP verification code using Resend Python SDK.
        """
        resend_api_key = os.getenv("RESEND_API_KEY") or settings.RESEND_API_KEY
        email_from = os.getenv("EMAIL_FROM") or settings.EMAIL_FROM or "onboarding@resend.dev"
        subject = "Your SentinelAI verification code"
        html_body = f"<p>Welcome {first_name},</p><p>Your 6-digit verification code is: <strong>{otp_code}</strong></p><p>This code expires in 10 minutes.</p>"

        if not recipient_email or "@" not in recipient_email:
            logger.warning(f"Invalid recipient email '{recipient_email}'. Skipping OTP email dispatch.")
            return False

        if resend_api_key:
            try:
                import resend
                resend.api_key = resend_api_key
                resend.Emails.send({
                    "from": email_from,
                    "to": recipient_email,
                    "subject": subject,
                    "html": html_body
                })
                logger.info(f"OTP verification email sent via Resend to {recipient_email}")
                return True
            except Exception as e:
                logger.error(f"Failed to send email via Resend: {str(e)}")

        # Fallback to SMTP if configured
        if settings.SMTP_USER and settings.SMTP_PASSWORD:
            try:
                msg = MIMEMultipart("alternative")
                msg["Subject"] = subject
                msg["From"] = email_from
                msg["To"] = recipient_email
                msg.attach(MIMEText(html_body, "html"))

                with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
                    server.starttls()
                    server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                    server.sendmail(email_from, recipient_email, msg.as_string())
                
                logger.info(f"OTP verification email sent via SMTP to {recipient_email}")
                return True
            except Exception as e:
                logger.error(f"Failed to send email via SMTP: {str(e)}")
        
        logger.warning(f"Resend/SMTP credentials missing. Unable to send verification email to {recipient_email}.")
        return False

    @staticmethod
    def send_support_ticket_email(admin_email: str, reporter_name: str, reporter_email: str, subject: str, description: str, ticket_id: str) -> bool:
        resend_api_key = os.getenv("RESEND_API_KEY") or settings.RESEND_API_KEY
        email_from = os.getenv("EMAIL_FROM") or settings.EMAIL_FROM or "onboarding@resend.dev"
        target_email = admin_email or os.getenv("ADMIN_NOTIFY_EMAIL") or settings.ADMIN_NOTIFY_EMAIL or reporter_email

        if not target_email or "@" not in target_email:
            logger.warning(f"Invalid or empty target email '{target_email}' for support ticket #{ticket_id}. Skipping Resend dispatch.")
            return False

        email_subject = f"[Support Ticket #{ticket_id}] {subject}"
        html_body = f"""
        <h3>📩 New SentinelAI Support Ticket Submitted</h3>
        <p><strong>Ticket ID:</strong> {ticket_id}</p>
        <p><strong>Reporter Name:</strong> {reporter_name}</p>
        <p><strong>Reporter Email:</strong> {reporter_email}</p>
        <p><strong>Subject:</strong> {subject}</p>
        <hr/>
        <h4>Description:</h4>
        <p style="white-space: pre-wrap;">{description}</p>
        """

        if resend_api_key:
            try:
                import resend
                resend.api_key = resend_api_key
                resend.Emails.send({
                    "from": email_from,
                    "to": target_email,
                    "subject": email_subject,
                    "html": html_body
                })
                logger.info(f"Support ticket email sent via Resend to {target_email}")
                return True
            except Exception as e:
                logger.error(f"Failed to send ticket email via Resend: {str(e)}")

        return False


