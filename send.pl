#!/usr/bin/perl

use strict;
use warnings;
use Net::SMTP;
use Mail::DKIM::Signer;
use Socket qw(AF_INET AF_INET6);

# ============================================================
# CONFIG
# ============================================================

my $DOMAIN   = "sujoy-z.us.to";
my $SELECTOR = "default";

my $FROM = "test\@$DOMAIN";

# ============================================================
# HARD-CODED DKIM PRIVATE KEY
# ============================================================

my $PRIVATE_KEY = <<'KEY';
-----BEGIN RSA PRIVATE KEY-----
MIIEoQIBAAKCAQBO82BpbAzXdjOuHf0WLoviN3SCDVsAY5ueybaieV43i9Inl5lB
Hgp9XGIBad9bQ34EkIIxQMn3niQuf5mFF91ddXJwlqp8gNVsGZcXaU4lMxoeXsHA
AKXpIKpnrSfQ0xXZQr2OSdiYVtpJEeUnT/zoJKgWjdlstIMbnbei4gy8kLSpEPc8
6BuuUUGPWVRtlKMWw40ahPG484czKg6NFIAVNRfstxOoZ+7OMzUaErBg+O/fQDft
GkDceGYFBgJYDV7CMy3gOi3poivSLRF5mch9ynayVI+q6ZtIhOzUpKgy6+5jaN89
WZxJHO+b41R+y2vIo3+xt0E9J1tQ0YH42/yxAgMBAAECggEAGkXRUqO7TkQuhIXE
QApzUG9l3RV2sBV1pwy3MzAyU0e7QqOnQ00s7nS8xH2n72XxXLF+Mce+riE5JyQd
QXYkm0JHOAJbb50r6JJHfmnzsFtmGK8tyKgujfrp2iB8PHjSL3+PNveKFX/pmiFT
YZazscjpCsBfl1YmvxzoDFMvK9yZHPSGYb8MehUrLbs/HaVr697DKXuylDagl0ni
sPlQydeApWmcNsX9f0Egp6fi699j/j44KNTYVh8v+yaROahBnFfSKRpIchw5udyf
iddHxlMvOG0MfQ5Qe8KTOc8aIVbdrp/71K4Vz+iuwkngVYbGVDF2TIUIETV7v5wY
YgkNtQKBgQCUabnhvRL93gt779y09bFg+E7e3Yl1bzOibHeAyxFiyb51YUbyL/e/
tXfpto6CymYXTPR1RntdRE5pxCSCCpivbpBfBcyNBfgXGXMFE9LLDgQTFqC4ELRF
yN7V9NgGmmEsV8CDFqDj/B+edWVAyvg85TVp2e7hUtI+Pl1tnmVsqwKBgQCILu8v
P/uji9GwacF4PYHJ6mZ3FsOiUjXgmSu9arnt2MnvjHrOIs4cRvwdQoaB2SxETENN
17vJZRus2g8TlH18RRlSzdbwFTQpARnQ+RVA6bBrnkgh/5IVXx8QbOa544+2Fxg7
asr0lq01CZvfhWYW30z0QonWhx03ZmJIzGbEEwKBgHw5DnwzLR1O6N/hAiR5bfHT
hPioB7FC1b5C+bfUwQWmBYPsW1zF56IQO4Fk613wGYmxQQCUcRe838FJiqFKS0iz
y6WtjewQLfrvs0VxtUN+xMxRaU8HtEyg+Fuvp83HFETwYlOW8i5Bzxlr+8dC3Irj
81RZNMhm8VFmE/930D8nAoGALbV7KKPUJW+voQPOITqbzpbzb3NflKL9XHZs3PXu
lCuYk+PV8Ex0W79jrbp/hSPMnNvwFzea2x0prdm/B7ZmbAiRWF6ojwq+6Chrbt27
yX7mbSjCU08BzFSSC6RRyQDdYqPbyU2t82yDlHK2M88FlhW7MZ0HwM62+rpNsNuS
fqsCgYAKCrUANn9fVDFWQCE7W6Tn4K/fu4PBsd1FHNzEy0xvwqS8bgzb3CM5Lws4
1WEpfQgeAyNQGkqjUQPcQYW215/szvgbxplJPUWzWw+juqoXzs/Ok0w48aDiTAkF
vjZDKUYH/sXK7D+jbEyE5rA8CFfp38QSeisYpCF67wL/FZGWFg==
-----END RSA PRIVATE KEY-----
KEY

# If your key is RSA format, use:
#
# -----BEGIN RSA PRIVATE KEY-----
# ...
# -----END RSA PRIVATE KEY-----

# ============================================================
# GMAIL MX
# ============================================================

my $SMTP_SERVER = "gmail-smtp-in.l.google.com";
my $SMTP_PORT   = 25;

# ============================================================
# VALIDATE EMAIL
# ============================================================

sub valid_email {
    my ($email) = @_;

    return 0 unless defined $email;
    return 0 unless $email =~ /^[^\s\@]+\@[^\s\@]+\.[^\s\@]+$/;

    return 1;
}

# ============================================================
# SEND EMAIL
# ============================================================

sub send_email {

    my ($to, $subject, $body) = @_;

    print "\n[*] Creating message...\n";

    # --------------------------------------------------------
    # MESSAGE
    # --------------------------------------------------------

    my $date = scalar(gmtime()) . " +0000";

    my $message =
          "From: <$FROM>\r\n"
        . "To: <$to>\r\n"
        . "Subject: $subject\r\n"
        . "Date: $date\r\n"
        . "Message-ID: <"
        . time()
        . "."
        . int(rand(1000000))
        . "\@$DOMAIN>\r\n"
        . "MIME-Version: 1.0\r\n"
        . "Content-Type: text/plain; charset=UTF-8\r\n"
        . "Content-Transfer-Encoding: 8bit\r\n"
        . "\r\n"
        . $body
        . "\r\n";

    # --------------------------------------------------------
    # DKIM SIGNATURE
    # --------------------------------------------------------

    print "[*] Signing message with DKIM...\n";

    my $dkim;

    eval {

        $dkim = Mail::DKIM::Signer->new(
            Algorithm => "rsa-sha256",
            Method    => "relaxed/simple",
            Domain    => $DOMAIN,
            Selector  => $SELECTOR,
            Key       => $PRIVATE_KEY,
        );

        $dkim->PRINT($message);
        $dkim->CLOSE();

    };

    if ($@) {

        print "[!] DKIM error: $@\n";

        return 0;
    }

    my $signature = $dkim->signature;

    unless ($signature) {

        print "[!] Failed to generate DKIM signature\n";

        return 0;
    }

    my $dkim_header = $signature->as_string;

    $message = $dkim_header . "\r\n" . $message;

    print "[+] DKIM signature generated\n";

    # --------------------------------------------------------
    # CONNECT TO GMAIL MX
    # --------------------------------------------------------

    print "[*] Connecting to $SMTP_SERVER:$SMTP_PORT...\n";

    my $smtp = Net::SMTP->new(
        $SMTP_SERVER,
        Port    => $SMTP_PORT,
        Timeout => 20,
        Debug   => 0,
    );

    unless ($smtp) {

        print "[!] Could not connect to Gmail MX\n";

        return 0;
    }

    print "[+] Connected to Gmail MX\n";

    # --------------------------------------------------------
    # MAIL FROM
    # --------------------------------------------------------

    unless ($smtp->mail($FROM)) {

        print "[!] MAIL FROM rejected\n";

        $smtp->quit();

        return 0;
    }

    print "[+] MAIL FROM accepted\n";

    # --------------------------------------------------------
    # RCPT TO
    # --------------------------------------------------------

    unless ($smtp->to($to)) {

        print "[!] RCPT TO rejected\n";

        $smtp->quit();

        return 0;
    }

    print "[+] RCPT TO accepted\n";

    # --------------------------------------------------------
    # DATA
    # --------------------------------------------------------

    unless ($smtp->data()) {

        print "[!] DATA command rejected\n";

        $smtp->quit();

        return 0;
    }

    $smtp->datasend($message);

    unless ($smtp->dataend()) {

        print "[!] Gmail rejected message after DATA\n";

        $smtp->quit();

        return 0;
    }

    # --------------------------------------------------------
    # SUCCESS
    # --------------------------------------------------------

    print "\n";
    print "========================================\n";
    print "        EMAIL ACCEPTED BY SERVER\n";
    print "========================================\n";
    print "From     : $FROM\n";
    print "To       : $to\n";
    print "Subject  : $subject\n";
    print "DKIM     : $SELECTOR._domainkey.$DOMAIN\n";
    print "SMTP     : $SMTP_SERVER:$SMTP_PORT\n";
    print "========================================\n";

    $smtp->quit();

    return 1;
}

# ============================================================
# MAIN LOOP
# ============================================================

$SIG{INT} = sub {

    print "\n\nExiting...\n";

    exit 0;
};

print "\n";
print "========================================\n";
print "       DIRECT SMTP MAIL SENDER\n";
print "========================================\n";
print "Domain  : $DOMAIN\n";
print "From    : $FROM\n";
print "Server  : $SMTP_SERVER:$SMTP_PORT\n";
print "DKIM    : $SELECTOR._domainkey.$DOMAIN\n";
print "========================================\n";

while (1) {

    print "\n";

    # --------------------------------------------------------
    # RECEIVER
    # --------------------------------------------------------

    print "Receiver email: ";

    my $to = <STDIN>;

    last unless defined $to;

    chomp($to);

    $to =~ s/^\s+//;
    $to =~ s/\s+$//;

    if ($to eq "") {

        print "[!] Receiver cannot be empty.\n";

        next;
    }

    unless (valid_email($to)) {

        print "[!] Invalid email address.\n";

        next;
    }

    # --------------------------------------------------------
    # SUBJECT
    # --------------------------------------------------------

    print "Title: ";

    my $subject = <STDIN>;

    last unless defined $subject;

    chomp($subject);

    if ($subject eq "") {

        print "[!] Title cannot be empty.\n";

        next;
    }

    # Remove CR/LF to prevent header injection
    $subject =~ s/[\r\n]+/ /g;

    # --------------------------------------------------------
    # BODY
    # --------------------------------------------------------

    print "Body: ";

    my $body = <STDIN>;

    last unless defined $body;

    chomp($body);

    if ($body eq "") {

        print "[!] Body cannot be empty.\n";

        next;
    }

    # --------------------------------------------------------
    # SEND
    # --------------------------------------------------------

    send_email(
        $to,
        $subject,
        $body
    );

    print "\n[*] Ready for next email...\n";
}
