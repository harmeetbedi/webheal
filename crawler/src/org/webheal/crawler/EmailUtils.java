package org.webheal.crawler;

import java.io.File;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.mail.DefaultAuthenticator;
import org.apache.commons.mail.EmailAttachment;
import org.apache.commons.mail.EmailException;
import org.apache.commons.mail.MultiPartEmail;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

public class EmailUtils
{
    private static final String EMAIL_FROM = System.getProperty("email.from","noreply@indusface.com");
    private static final String EMAIL_PASSWORD = System.getProperty("email.password","ifc@12345");
    
    public static void main(String[] args) throws EmailException
    {
        EmailUtils.sendEmail(EMAIL_FROM, EMAIL_PASSWORD, Arrays.asList("harmeet@kodemuse.com"), "Hello", "There", null);
    }
    public static void sendEmail(String mailTo, String subject, String body) throws EmailException
    {
        sendEmail(EMAIL_FROM, EMAIL_PASSWORD, Arrays.asList(mailTo), subject, body, null);
    }
    public static void sendAsyncEmail(final String mailTo, final String subject, final String body) throws EmailException
    {
        Runnable r = new Runnable() {
            public void run()
            {
                try {
                    sendEmail(EMAIL_FROM, EMAIL_PASSWORD, Arrays.asList(mailTo), subject, body, null);
                } catch (Throwable e) {
                    Logger.getLogger(EmailUtils.class).error("AsyncMail Failed: "+mailTo+", "+subject,e);
                }
            }
        };
        new Thread(r,"EmailSend:"+mailTo).start();
    }
    public static void sendEmail(List<String> mailTo, String subject, String body, List<File> attachments) throws EmailException
    {
        sendEmail(EMAIL_FROM, EMAIL_PASSWORD, mailTo, subject, body, null);
    }
    public static void sendEmail(String userid, String password, List<String> mailTo, String subject, String body, List<File> attachments)
            throws EmailException
    {
        MultiPartEmail email = createEmail(userid, password, mailTo, subject, body, attachments);
        send(email);
    }
    
    public static void send(MultiPartEmail email) throws EmailException {
        long start = System.currentTimeMillis();
        boolean success = false;
        try {
            email.send();
            success = true;
        } finally {
            Level level = success ? Level.INFO : Level.ERROR;
            long tt = System.currentTimeMillis() - start;
            Logger.getLogger(EmailUtils.class).log(level, "SendEmail - TimeTaken:"+tt+", EmailTo:"+email.getToAddresses()+", Subject:"+email.getSubject());
        }
    }

    public static MultiPartEmail createEmail(String mailTo, String subject, String body, File attachment) throws EmailException
    {
        return createEmail(EMAIL_FROM, EMAIL_PASSWORD, Arrays.asList(mailTo), subject, body, attachment == null ? null : Arrays.asList(attachment));
    }
    private static MultiPartEmail createEmail(String userid, String password, List<String> mailTo, String subject, String body,
            List<File> attachments) throws EmailException
    {
        MultiPartEmail email = new MultiPartEmail();
        email.setHostName("smtp.office365.com");
        email.setSmtpPort(587);
        email.setAuthenticator(new DefaultAuthenticator(userid, password));
        email.setTLS(true);
        // email.setSSL(true);

        email.setFrom(userid);
        for (String to : mailTo) {
            email.addTo(to);
        }
        email.setSubject(subject);
        email.setMsg(body);
        if (attachments != null) {
            for (File file : attachments) {
                EmailAttachment attach = new EmailAttachment();
                attach.setPath(file.getAbsolutePath());
                email.attach(attach);
            }
        }
        return email;
    }
}