import email, smtplib, ssl, getpass
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

def get_message(sender_email, sender_name, emails, receiver_names, fname, subject):
    # Create a multipart message and set headers
    body = "Dear " + receiver_names + ",<br><br>" + f"""\
            Please find attached the {subject} for encryption
            """
    message = MIMEMultipart()
    message["From"] =  sender_name+"<"+sender_email+">"
    message["To"] = receiver_names + "<" + emails + ">"
    message["Subject"] = subject
    # message["Bcc"] = "krishvi-dhavala-committee@googlegroups.com"

    # Add body to email
    message.attach(MIMEText(body, "html"))

    # In same directory as script
    files = [fname]

    for f in files:
        # Add file as application/octet-stream
        # Email client can usually download this automatically as attachment
        part = MIMEBase('application', "octet-stream")
        # Open PDF file in binary mode
        part.set_payload(open(f, "rb").read())
        # Encode file in ASCII characters to send by email
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f"attachment; filename= {f}",)
        # Add attachment to message
        message.attach(part)

    # Convert message to string
    return message.as_string()

def mailto(sender_email, sender_name, receiver_emails, receiver_names, fname, subject):
    #sender_email = "achyub@gmail.com"
    #receiver_emails = "achyut.22068@gear.ac.in"
    password = getpass.getpass("Type your password and press enter:")
    # Log in to server using secure context and send email
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        server.login(sender_email, password)
        #now = datetime.now().strftime("%m-%d-%Y-%H:%M:%S")
        emails = receiver_emails.split(',')
        print(f"Sending email with email ids: {receiver_emails}")
        for i in range(0,len(emails)):
          text = get_message(sender_email, sender_name, emails[i], receiver_names[i], fname, subject)
          server.sendmail(sender_email, emails[i], text)
