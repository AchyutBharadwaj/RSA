module Mail

export sendmail

using SMTPClient
using Dates
using Base64

const bset = [collect('A':'Z'); collect('a':'z'); collect('0':'9')]

function sendmail(;from=(name=nothing, mail=nothing),
                   tolist=[(name=nothing, mail=nothing)],
                   subject="", message="",
                   attachfiles=nothing, url="smtps://smtp.gmail.com:465")

  ret = 0

  secret = Base.getpass("Password")
  passwd = string(Char.(secret.data)...)
  Base.shred!(secret)

  for to in tolist
    date = "Date: "*Dates.format(now(),"e, d u Y HH:MM:SS")*" +0530 (IST)\r\n"
    opt = SendOptions(isSSL = true, username = from.mail, passwd = passwd)
    boundary = string(rand(bset,20)...)
    sub = replace(subject, r"(\$receiver)"=>to.name)
    msg = replace(message, r"(\$receiver)"=>to.name)
    msg = replace(msg, r"(\$subject)"=>sub)

    attach = ""
    if attachfiles !== nothing
      for afile in attachfiles
        attachment = base64encode(read(afile))
        attach *= "--$boundary\r\n" *
                  "Content-Type: application/octet-stream\r\n" *
                  "Content-Transfer-Encoding: base64\r\n" *
                  "Content-Disposition: attachment; filename=$afile\r\n" *
                  "\r\n" *
                  "$attachment" * "\r\n"
      end
    end

    body = IOBuffer(date * "From: $(from.name) <$(from.mail)>\r\n" *
                           "To: $(to.name) <$(to.mail)>\r\n" *
                           "Subject: $sub\r\n" *
                           "Content-Type: multipart/mixed; boundary=$boundary\r\n" *
                           "MIME-Version: 1.0\r\n" *
                           "--$boundary\r\n" *
                           "Content-Type: text/html; charset=\"us-ascii\"" *
                           "\r\n" *
                           msg * "\r\n" *
                           attach *
                           "--$boundary--" * "\r\n"
                   )
    
    try
      resp = send(url, [to.mail], from.mail, body, opt)
      println("Sending $subject to $(to.mail)")
      ret = 1
    catch
      ret = 0
    end
  end

  if ret == 0
    println("Incorrect password. Try again.")
  end
  return ret

end

end
