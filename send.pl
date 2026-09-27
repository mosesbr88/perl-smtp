#!/usr/bin/perl

use strict;
use warnings;

use Net::SMTP;
use Net::DNS;
use Socket qw(AF_INET6);

use LWP::UserAgent;

use Mail::DKIM::Signer;
use Mail::DKIM::PrivateKey;
use Mail::DKIM::TextWrap;

use File::Temp qw(tempfile);
use POSIX qw(strftime);

# ============================================================
# CONFIG
# ============================================================

my $DOMAIN       = "sujoy-z.us.to";
my $SELECTOR     = "default";
my $FROM         = "test\@$DOMAIN";

# Put your NEW/ROTATED private DKIM key URL here.
#
# Do NOT use the previously exposed public private-key file.
my $KEY_URL = "https://raw.githubusercontent.com/mosesbr88/perl-smtp/refs/heads/main/pvt.txt";

my $HELO_DOMAIN = $DOMAIN;

# ============================================================
# DNS RESOLVER
# ============================================================

my $resolver = Net::DNS::Resolver->new(
    udp_timeout => 5,
    tcp_timeout => 10,
    retry       => 2
);

# ============================================================
# LOAD DKIM PRIVATE KEY
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

    unless (
        $key_data =~ /-----BEGIN RSA PRIVATE KEY-----/
        ||
        $key_data =~ /-----BEGIN PRIVATE KEY-----/
    ) {
        die "Downloaded file does not contain a valid PEM private key.\n";
    }

    my ($fh, $filename) = tempfile(
        "dkim-XXXXXX",
        SUFFIX => ".pem",
        UNLINK => 1
    );

    print $fh $key_data
        or die "Unable to write temporary DKIM key.\n";

    close $fh
        or die "Unable to close temporary DKIM key.\n";

    my $private_key = Mail::DKIM::PrivateKey->load(
        File => $filename
    );

    die "Unable to load DKIM private key.\n"
        unless $private_key;

    print "DKIM private key loaded.\n";

    return $private_key;
}

# ============================================================
# EXTRACT DOMAIN FROM EMAIL
# ============================================================

sub get_domain {

    my ($email) = @_;

    my ($domain) = $email =~ /\@([^\@]+)$/;

    return unless $domain;

    $domain =~ s/\.$//;

    return lc($domain);
}

# ============================================================
# FIND MX RECORDS
# ============================================================

sub get_mx_records {

    my ($domain) = @_;

    print "\n";
    print "Looking up MX records for: $domain\n";

    my @mx = Net::DNS::mx(
        $resolver,
        $domain
    );

    unless (@mx) {
        print "No MX records found for $domain\n";
        return;
    }

    print "MX records found:\n";

    foreach my $mx (@mx) {

        my $host = $mx->exchange;
        my $pref = $mx->preference;

        print "  Preference $pref -> $host\n";
    }

    return @mx;
}

# ============================================================
# GET AAAA RECORDS
# ============================================================

sub get_ipv6_addresses {

    my ($hostname) = @_;

    print "Looking up AAAA: $hostname\n";

    my $packet = $resolver->query(
        $hostname,
        "AAAA"
    );

    unless ($packet) {
        print "  AAAA lookup failed: "
            . $resolver->errorstring . "\n";

        return;
    }

    my @addresses;

    foreach my $rr ($packet->answer) {

        next unless $rr->type eq "AAAA";

        my $address = $rr->address;

        push @addresses, $address;

        print "  IPv6: $address\n";
    }

    unless (@addresses) {
        print "  No IPv6 address found.\n";
    }

    return @addresses;
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
# DKIM SIGN
# ============================================================

sub sign_message {

    my ($private_key, $message) = @_;

    my $signer = Mail::DKIM::Signer->new(

        Algorithm => "rsa-sha256",

        Method => "relaxed",

        Domain => $DOMAIN,

        Selector => $SELECTOR,

        Key => $private_key,

        Headers => [
            "From",
            "To",
            "Subject",
            "Date",
            "Message-ID"
        ]
    );

    # DKIM requires CRLF
    $message =~ s/\r?\n/\r\n/g;

    $signer->PRINT($message);

    $signer->CLOSE();

    my $signature = $signer->signature;

    die "DKIM signature generation failed.\n"
        unless $signature;

    my $dkim_header = $signature->as_string;

    return $dkim_header
        . "\r\n"
        . $message;
}

# ============================================================
# CONNECT TO MX OVER IPV6 + STARTTLS
# ============================================================

sub connect_mx_ipv6 {

    my ($mx_host) = @_;

    print "\n";
    print "Trying MX: $mx_host\n";

    # --------------------------------------------------------
    # Check AAAA first
    # --------------------------------------------------------

    my @ipv6 = get_ipv6_addresses($mx_host);

    unless (@ipv6) {

        print "Skipping $mx_host because it has no AAAA record.\n";

        return;
    }

    # --------------------------------------------------------
    # Connect using IPv6
    #
    # Family => AF_INET6 forces IPv6.
    # Host remains the MX hostname so TLS certificate
    # verification uses the hostname rather than the IP.
    # --------------------------------------------------------

    print "Connecting to $mx_host:25 over IPv6...\n";

    my $smtp = Net::SMTP->new(

        Host => $mx_host,

        Port => 25,

        Hello => $HELO_DOMAIN,

        Timeout => 30,

        Family => AF_INET6,

        Debug => 0
    );

    unless ($smtp) {

        print "IPv6 SMTP connection failed for $mx_host\n";

        return;
    }

    print "IPv6 SMTP connection established.\n";

    # --------------------------------------------------------
    # STARTTLS
    # --------------------------------------------------------

    print "Starting STARTTLS...\n";

    my $tls_ok = eval {

        $smtp->starttls(

            SSL_verify_mode => 1,

            SSL_hostname => $mx_host
        );
    };

    if (!$tls_ok) {

        print "STARTTLS failed for $mx_host\n";

        eval {
            $smtp->quit();
        };

        return;
    }

    print "STARTTLS established successfully.\n";

    # --------------------------------------------------------
    # EHLO again after STARTTLS
    # --------------------------------------------------------

    unless ($smtp->hello($HELO_DOMAIN)) {

        print "EHLO after STARTTLS failed.\n";

        eval {
            $smtp->quit();
        };

        return;
    }

    print "EHLO after STARTTLS successful.\n";

    return $smtp;
}

# ============================================================
# SEND MAIL
# ============================================================

sub send_mail {

    my (
        $to,
        $subject,
        $body,
        $private_key
    ) = @_;

    # --------------------------------------------------------
    # Get recipient domain
    # --------------------------------------------------------

    my $recipient_domain = get_domain($to);

    die "Unable to determine recipient domain.\n"
        unless $recipient_domain;

    print "\n";
    print "Recipient : $to\n";
    print "Domain    : $recipient_domain\n";

    # --------------------------------------------------------
    # MX LOOKUP
    # --------------------------------------------------------

    my @mx_records =
        get_mx_records($recipient_domain);

    die "No MX records available for $recipient_domain.\n"
        unless @mx_records;

    # --------------------------------------------------------
    # CREATE MESSAGE
    # --------------------------------------------------------

    my $message = create_message(
        $to,
        $subject,
        $body
    );

    # --------------------------------------------------------
    # DKIM SIGN
    # --------------------------------------------------------

    print "\nGenerating DKIM signature...\n";

    my $signed_message = sign_message(
        $private_key,
        $message
    );

    print "DKIM signature generated.\n";

    # --------------------------------------------------------
    # TRY MX RECORDS IN PREFERENCE ORDER
    # --------------------------------------------------------

    foreach my $mx (@mx_records) {

        my $mx_host = $mx->exchange;

        # Remove final DNS dot
        $mx_host =~ s/\.$//;

        my $preference = $mx->preference;

        print "\n";
        print "========================================\n";
        print "MX Preference : $preference\n";
        print "MX Host       : $mx_host\n";
        print "========================================\n";

        # ----------------------------------------------------
        # CONNECT IPv6 + STARTTLS
        # ----------------------------------------------------

        my $smtp =
            connect_mx_ipv6($mx_host);

        unless ($smtp) {

            print "MX failed. Trying next MX...\n";

            next;
        }

        # ----------------------------------------------------
        # MAIL FROM
        # ----------------------------------------------------

        print "MAIL FROM: $FROM\n";

        unless ($smtp->mail($FROM)) {

            print "MAIL FROM failed.\n";

            eval {
                $smtp->quit();
            };

            next;
        }

        # ----------------------------------------------------
        # RCPT TO
        # ----------------------------------------------------

        print "RCPT TO: $to\n";

        unless ($smtp->to($to)) {

            print "RCPT TO failed.\n";

            eval {
                $smtp->quit();
            };

            next;
        }

        # ----------------------------------------------------
        # DATA
        # ----------------------------------------------------

        print "Sending DATA...\n";

        unless ($smtp->data()) {

            print "DATA command failed.\n";

            eval {
                $smtp->quit();
            };

            next;
        }

        unless ($smtp->datasend($signed_message)) {

            print "Failed to send message data.\n";

            eval {
                $smtp->quit();
            };

            next;
        }

        unless ($smtp->dataend()) {

            print "DATA END failed.\n";

            eval {
                $smtp->quit();
            };

            next;
        }

        # ----------------------------------------------------
        # SUCCESS
        # ----------------------------------------------------

        print "\n";
        print "========================================\n";
        print "MESSAGE ACCEPTED BY MX\n";
        print "========================================\n";
        print "MX       : $mx_host\n";
        print "IPv6     : YES\n";
        print "STARTTLS : YES\n";
        print "DKIM     : YES\n";
        print "========================================\n";

        eval {
            $smtp->quit();
        };

        return 1;
    }

    die "\nAll IPv6 MX servers failed.\n";
}

# ============================================================
# LOAD DKIM KEY
# ============================================================

my $dkim_key = load_dkim_key();

# ============================================================
# START
# ============================================================

print "\n";
print "========================================\n";
print "AUTOMATIC MX SMTP SENDER\n";
print "========================================\n";
print "From       : $FROM\n";
print "Domain     : $DOMAIN\n";
print "IPv6       : ENABLED\n";
print "STARTTLS   : REQUIRED\n";
print "DKIM       : ENABLED\n";
print "MX lookup  : AUTOMATIC\n";
print "========================================\n";

# ============================================================
# SEND LOOP
# ============================================================

while (1) {

    print "\nReceiver email (or 'exit'): ";

    my $to = <STDIN>;

    last unless defined $to;

    chomp $to;

    last if lc($to) eq "exit";

    # --------------------------------------------------------
    # Basic email validation
    # --------------------------------------------------------

    unless (
        $to =~
        /^[A-Za-z0-9.!#\$%&'*+\/=?^_`{|}~-]+\@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/
    ) {

        print "Invalid email address.\n";

        next;
    }

    # --------------------------------------------------------
    # Subject
    # --------------------------------------------------------

    print "Subject: ";

    my $subject = <STDIN>;

    last unless defined $subject;

    chomp $subject;

    # Prevent SMTP header injection
    $subject =~ s/[\r\n]//g;

    # --------------------------------------------------------
    # Body
    # --------------------------------------------------------

    print "Body: ";

    my $body = <STDIN>;

    last unless defined $body;

    chomp $body;

    # --------------------------------------------------------
    # SEND
    # --------------------------------------------------------

    eval {

        send_mail(
            $to,
            $subject,
            $body,
            $dkim_key
        );
    };

    if ($@) {

        print "\n";
        print "========================================\n";
        print "SEND FAILED\n";
        print "========================================\n";
        print $@;
    }
    else {

        print "\nMail sent successfully.\n";
    }
}
