#!/usr/bin/perl

use strict;
use warnings;

use Net::SMTP;
use Socket qw(AF_INET6);
use LWP::UserAgent;

use Mail::DKIM::Signer;
use Mail::DKIM::PrivateKey;
use Mail::DKIM::TextWrap;

use File::Temp qw(tempfile);
use POSIX qw(strftime);

# ============================================================
# CONFIGURATION
# ============================================================

my $DOMAIN      = "sujoy-z.us.to";
my $SELECTOR    = "default";
my $FROM        = "test\@$DOMAIN";

# Gmail receiving MX
my $SMTP_SERVER = "gmail-smtp-in.l.google.com";
my $SMTP_PORT   = 25;

# IMPORTANT:
# Do NOT put your previously exposed private key URL here.
# Use a NEW/ROTATED DKIM private key stored somewhere private.
my $KEY_URL = "https://raw.githubusercontent.com/mosesbr88/perl-smtp/refs/heads/main/pvt.txt";

# Your SMTP server hostname used in EHLO
my $HELO_DOMAIN = $DOMAIN;

# ============================================================
# DOWNLOAD DKIM PRIVATE KEY
# ============================================================

sub load_dkim_key {

    print "Downloading DKIM private key...\n";

    my $ua = LWP::UserAgent->new(
        timeout => 20,
        agent   => "Perl-SMTP/1.0"
    );

    my $response = $ua->get($KEY_URL);

    die "Failed to download DKIM key: "
        . $response->status_line . "\n"
        unless $response->is_success;

    my $key_data = $response->decoded_content;

    # Basic PEM validation
    unless (
        $key_data =~ /-----BEGIN RSA PRIVATE KEY-----/
        ||
        $key_data =~ /-----BEGIN PRIVATE KEY-----/
    ) {
        die "Downloaded file does not look like a PEM private key.\n";
    }

    # Create temporary PEM file
    my ($fh, $filename) = tempfile(
        "dkim-XXXXXX",
        SUFFIX => ".pem",
        UNLINK => 1
    );

    print $fh $key_data;
    close $fh;

    # Mail::DKIM::PrivateKey officially supports loading from File
    my $private_key = Mail::DKIM::PrivateKey->load(
        File => $filename
    );

    die "Could not load DKIM private key.\n"
        unless $private_key;

    print "DKIM private key loaded successfully.\n";

    return $private_key;
}

# ============================================================
# CREATE DKIM SIGNATURE
# ============================================================

sub sign_message {

    my ($private_key, $message) = @_;

    my $signer = Mail::DKIM::Signer->new(
        Algorithm => "rsa-sha256",
        Method    => "relaxed",
        Domain    => $DOMAIN,
        Selector  => $SELECTOR,
        Key       => $private_key,

        Headers   => [
            "From",
            "To",
            "Subject",
            "Date",
            "Message-ID"
        ]
    );

    # Mail::DKIM expects SMTP-style CRLF
    $message =~ s/\r?\n/\r\n/g;

    $signer->PRINT($message);
    $signer->CLOSE();

    my $signature = $signer->signature;

    die "DKIM signature generation failed.\n"
        unless $signature;

    my $dkim_header = $signature->as_string;

    # TextWrap handles proper DKIM header folding.
    return $dkim_header . "\r\n" . $message;
}

# ============================================================
# CREATE MESSAGE
# ============================================================

sub create_message {

    my ($to, $subject, $body) = @_;

    my $date = strftime(
        "%a, %d %b %Y %H:%M:%S %z",
        localtime
    );

    my $message_id =
        "<"
        . time()
        . "."
        . int(rand(1000000))
        . "\@$DOMAIN>";

    my $message = <<"EOF";
From: $FROM
To: $to
Subject: $subject
Date: $date
Message-ID: $message_id
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit

$body
EOF

    return $message;
}

# ============================================================
# SEND USING IPv6 + STARTTLS
# ============================================================

sub send_mail {

    my ($to, $subject, $body, $private_key) = @_;

    print "\n";
    print "========================================\n";
    print "Connecting to Gmail MX over IPv6...\n";
    print "Server : $SMTP_SERVER\n";
    print "Port   : $SMTP_PORT\n";
    print "========================================\n";

    # Force IPv6.
    #
    # Net::SMTP passes Family to the underlying socket.
    # AF_INET6 prevents fallback to IPv4.
    my $smtp = Net::SMTP->new(
        Host        => $SMTP_SERVER,
        Port        => $SMTP_PORT,
        Hello       => $HELO_DOMAIN,
        Timeout     => 30,
        Family      => AF_INET6,
        Debug       => 0
    );

    die "IPv6 SMTP connection failed.\n"
        unless $smtp;

    print "IPv6 connection established.\n";

    # ========================================================
    # STARTTLS
    # ========================================================

    print "Starting STARTTLS...\n";

    my $tls_ok = $smtp->starttls(
        SSL_verify_mode => 1,
        SSL_hostname    => $SMTP_SERVER
    );

    die "STARTTLS negotiation failed.\n"
        unless $tls_ok;

    print "STARTTLS/TLS established successfully.\n";

    # ========================================================
    # EHLO AGAIN AFTER STARTTLS
    # ========================================================

    $smtp->hello($HELO_DOMAIN)
        or die "EHLO after STARTTLS failed.\n";

    print "EHLO after TLS successful.\n";

    # ========================================================
    # CREATE MESSAGE
    # ========================================================

    my $message = create_message(
        $to,
        $subject,
        $body
    );

    # ========================================================
    # DKIM SIGN
    # ========================================================

    print "Generating DKIM signature...\n";

    my $signed_message = sign_message(
        $private_key,
        $message
    );

    print "DKIM signature generated.\n";

    # ========================================================
    # SMTP ENVELOPE
    # ========================================================

    print "Sending MAIL FROM...\n";

    $smtp->mail($FROM)
        or die "MAIL FROM failed.\n";

    print "Sending RCPT TO...\n";

    $smtp->to($to)
        or die "RCPT TO failed for $to\n";

    print "Sending DATA...\n";

    $smtp->data()
        or die "DATA command failed.\n";

    $smtp->datasend($signed_message)
        or die "Failed to send message data.\n";

    $smtp->dataend()
        or die "DATA END failed.\n";

    print "\n";
    print "========================================\n";
    print "SMTP MESSAGE ACCEPTED BY GMAIL MX\n";
    print "========================================\n";

    $smtp->quit();

    print "Connection closed.\n";
}

# ============================================================
# LOAD KEY ONCE
# ============================================================

my $dkim_key = load_dkim_key();

print "\n";
print "========================================\n";
print "IPv6 + STARTTLS + DKIM SMTP SENDER\n";
print "Domain : $DOMAIN\n";
print "From   : $FROM\n";
print "MX     : $SMTP_SERVER:$SMTP_PORT\n";
print "========================================\n";

# ============================================================
# SEND LOOP
# ============================================================

while (1) {

    print "\nReceiver email (or 'exit'): ";
    chomp(my $to = <STDIN>);

    last if lc($to) eq "exit";

    unless ($to =~ /^[A-Za-z0-9.!#\$%&'*+\/=?^_`{|}~-]+\@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/) {
        print "Invalid email address.\n";
        next;
    }

    print "Subject: ";
    chomp(my $subject = <STDIN>);

    # Prevent header injection
    $subject =~ s/[\r\n]//g;

    print "Body: ";
    chomp(my $body = <STDIN>);

    eval {
        send_mail(
            $to,
            $subject,
            $body,
            $dkim_key
        );
    };

    if ($@) {
        print "\nSEND FAILED:\n$@\n";
    } else {
        print "\nMail sent successfully.\n";
    }
}
