
#!/usr/bin/perl

use strict;
use warnings;

use Net::SMTP;
use LWP::UserAgent;
use Mail::DKIM::Signer;
use Mail::DKIM::PrivateKey;
use Mail::DKIM::TextWrap;
use File::Temp qw(tempfile);
use POSIX qw(strftime);

# ============================================================
# CONFIG
# ============================================================

my $DOMAIN   = "sujoy-z.us.to";
my $SELECTOR = "default";

my $FROM = "test\@$DOMAIN";

my $SMTP_SERVER = "gmail-smtp-in.l.google.com";
my $SMTP_PORT   = 25;

# IMPORTANT:
# Use a PRIVATE URL for the DKIM private key.
# Do NOT keep the private key in a public GitHub repository.
my $KEY_URL = "https://raw.githubusercontent.com/mosesbr88/perl-smtp/refs/heads/main/pvt.txt";

# ============================================================
# DOWNLOAD PRIVATE KEY
# ============================================================

sub download_private_key {

    print "[*] Downloading DKIM private key...\n";

    my $ua = LWP::UserAgent->new(
        timeout => 20,
        agent   => "Perl-DKIM-Sender/1.0",
    );

    my $response = $ua->get($KEY_URL);

    unless ($response->is_success) {
        die "[DKIM ERROR] Cannot download private key: "
          . $response->status_line
          . "\n";
    }

    my $key = $response->decoded_content;

    # Remove UTF-8 BOM if present
    $key =~ s/^\x{FEFF}//;

    # Remove surrounding whitespace
    $key =~ s/^\s+//;
    $key =~ s/\s+$//;

    # Accept normal RSA PEM
    if ($key =~ /-----BEGIN RSA PRIVATE KEY-----/) {

        unless ($key =~ /-----END RSA PRIVATE KEY-----/) {
            die "[DKIM ERROR] RSA private key is incomplete.\n";
        }

    # Also accept PKCS#8 PEM
    } elsif ($key =~ /-----BEGIN PRIVATE KEY-----/) {

        unless ($key =~ /-----END PRIVATE KEY-----/) {
            die "[DKIM ERROR] PKCS#8 private key is incomplete.\n";
        }

    } else {

        die "[DKIM ERROR] Downloaded file does not contain a PEM private key.\n";
    }

    print "[+] Private key downloaded\n";

    return $key;
}

# ============================================================
# CREATE MAIL::DKIM::PrivateKey
# ============================================================

sub create_dkim_key {

    my ($pem) = @_;

    print "[*] Loading DKIM private key...\n";

    my ($fh, $filename) = tempfile(
        "dkim-key-XXXXXX",
        TMPDIR => 1,
        UNLINK => 1,
    );

    binmode($fh);

    print $fh $pem;

    close($fh)
        or die "[DKIM ERROR] Cannot close temporary key file: $!\n";

    my $dkim_key;

    eval {

        $dkim_key = Mail::DKIM::PrivateKey->load(
            File => $filename,
        );

    };

    if ($@ || !$dkim_key) {

        die
            "[DKIM ERROR] Cannot load DKIM private key.\n"
          . ($@ || "Unknown error")
          . "\n";
    }

    print "[+] DKIM private key loaded\n";

    return $dkim_key;
}

# ============================================================
# INITIALIZE DKIM
# ============================================================

my $PRIVATE_KEY_PEM = download_private_key();

my $DKIM_KEY = create_dkim_key($PRIVATE_KEY_PEM);

# ============================================================
# EMAIL VALIDATION
# ============================================================

sub valid_email {

    my ($email) = @_;

    return 0 unless defined $email;

    return 0 unless
        $email =~ /^[^\s\@]+\@[^\s\@]+\.[^\s\@]+$/;

    return 1;
}

# ============================================================
# SEND EMAIL
# ============================================================

sub send_email {

    my ($to, $subject, $body) = @_;

    print "\n";
    print "[*] Creating message...\n";

    # --------------------------------------------------------
    # DATE
    # --------------------------------------------------------

    my $date = strftime(
        "%a, %d %b %Y %H:%M:%S +0000",
        gmtime()
    );

    # --------------------------------------------------------
    # MESSAGE ID
    # --------------------------------------------------------

    my $message_id =
          time()
        . "."
        . int(rand(1000000))
        . "\@"
        . $DOMAIN;

    # --------------------------------------------------------
    # MESSAGE
    # --------------------------------------------------------

    my $message =
          "From: <$FROM>\r\n"
        . "To: <$to>\r\n"
        . "Subject: $subject\r\n"
        . "Date: $date\r\n"
        . "Message-ID: <$message_id>\r\n"
        . "MIME-Version: 1.0\r\n"
        . "Content-Type: text/plain; charset=UTF-8\r\n"
        . "Content-Transfer-Encoding: 8bit\r\n"
        . "\r\n"
        . $body
        . "\r\n";

    # --------------------------------------------------------
    # DKIM SIGNER
    # --------------------------------------------------------

    print "[*] Creating DKIM signature...\n";

    my $dkim;

    eval {

        $dkim = Mail::DKIM::Signer->new(
            Algorithm => "rsa-sha256",
            Method    => "relaxed",
            Domain    => $DOMAIN,
            Selector  => $SELECTOR,
            Key       => $DKIM_KEY,
        );

    };

    if ($@ || !$dkim) {

        print "[!] DKIM signer creation failed:\n";
        print $@ if $@;

        return 0;
    }

    # --------------------------------------------------------
    # FEED MESSAGE TO DKIM
    # --------------------------------------------------------

    eval {

        $dkim->PRINT($message);
        $dkim->CLOSE();

    };

    if ($@) {

        print "[!] DKIM signing failed:\n";
        print $@;

        return 0;
    }

    # --------------------------------------------------------
    # GET SIGNATURE
    # --------------------------------------------------------

    my $signature;

    eval {

        $signature = $dkim->signature();

    };

    if ($@ || !$signature) {

        print "[!] Could not generate DKIM signature\n";
        print $@ if $@;

        return 0;
    }

    # --------------------------------------------------------
    # DKIM HEADER
    # --------------------------------------------------------

    my $dkim_header;

    eval {

        $dkim_header = $signature->as_string();

    };

    if ($@ || !$dkim_header) {

        print "[!] Could not create DKIM header\n";
        print $@ if $@;

        return 0;
    }

    # Add DKIM header before all normal headers
    $message =
          $dkim_header
        . "\r\n"
        . $message;

    print "[+] DKIM signature generated\n";

    # --------------------------------------------------------
    # CONNECT TO GMAIL MX
    # --------------------------------------------------------

    print "[*] Connecting to "
        . $SMTP_SERVER
        . ":"
        . $SMTP_PORT
        . "...\n";

    my $smtp;

    eval {

        $smtp = Net::SMTP->new(
            $SMTP_SERVER,
            Port    => $SMTP_PORT,
            Timeout => 30,
            Hello   => $DOMAIN,
            Debug   => 0,
        );

    };

    if ($@) {

        print "[!] SMTP connection error:\n";
        print $@;

        return 0;
    }

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

    # --------------------------------------------------------
    # SEND MESSAGE
    # --------------------------------------------------------

    unless ($smtp->datasend($message)) {

        print "[!] Failed to send message data\n";

        $smtp->quit();

        return 0;
    }

    # --------------------------------------------------------
    # END DATA
    # --------------------------------------------------------

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
    print "       SMTP MESSAGE ACCEPTED\n";
    print "========================================\n";
    print "From    : $FROM\n";
    print "To      : $to\n";
    print "Subject : $subject\n";
    print "DKIM    : $SELECTOR._domainkey.$DOMAIN\n";
    print "Server  : $SMTP_SERVER:$SMTP_PORT\n";
    print "========================================\n";

    $smtp->quit();

    return 1;
}

# ============================================================
# CTRL+C
# ============================================================

$SIG{INT} = sub {

    print "\n\nExiting...\n";

    exit 0;
};

# ============================================================
# START
# ============================================================

print "\n";
print "========================================\n";
print "       DIRECT SMTP MAIL SENDER\n";
print "========================================\n";
print "Domain  : $DOMAIN\n";
print "From    : $FROM\n";
print "Server  : $SMTP_SERVER:$SMTP_PORT\n";
print "DKIM    : $SELECTOR._domainkey.$DOMAIN\n";
print "========================================\n";
print "[+] DKIM system initialized\n";

# ============================================================
# MAIN LOOP
# ============================================================

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

        print "[!] Receiver email cannot be empty.\n";

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

    # Prevent header injection
    $subject =~ s/[\r\n]+/ /g;

    if ($subject eq "") {

        print "[!] Title cannot be empty.\n";

        next;
    }

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

    print "\n";
    print "[*] Ready for next email...\n";
}
