#!/usr/bin/perl

use strict;
use warnings;

use Net::SMTP;
use Net::DNS;
use Socket qw(AF_INET AF_INET6);

use LWP::UserAgent;
use IO::Socket::SSL;

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
my $FROM     = "test\@$DOMAIN";

# IMPORTANT:
# Replace this with a NEW/private DKIM key URL.
#
# The previously posted public pvt.txt key should be rotated.
my $KEY_URL = "https://raw.githubusercontent.com/mosesbr88/perl-smtp/refs/heads/main/pvt.txt";

my $HELO_DOMAIN = $DOMAIN;
my $SMTP_PORT   = 25;

# ============================================================
# DNS RESOLVER
# ============================================================

my $resolver = Net::DNS::Resolver->new(
    udp_timeout => 5,
    tcp_timeout => 10,
    retry       => 2,
);

# ============================================================
# LOAD DKIM KEY
# ============================================================

sub load_dkim_key {

    print "Downloading DKIM private key...\n";

    my $ua = LWP::UserAgent->new(
        timeout => 20,
        agent   => "Perl-MX-SMTP/1.0",
    );

    my $response = $ua->get($KEY_URL);

    die "DKIM key download failed: "
        . $response->status_line . "\n"
        unless $response->is_success;

    my $key_data = $response->decoded_content;

    die "Downloaded file is not a PEM private key.\n"
        unless $key_data =~ /-----BEGIN (?:RSA )?PRIVATE KEY-----/;

    my ($fh, $filename) = tempfile(
        "dkim-XXXXXX",
        SUFFIX => ".pem",
        UNLINK => 1,
    );

    print $fh $key_data
        or die "Could not write temporary DKIM key.\n";

    close $fh
        or die "Could not close temporary DKIM key.\n";

    my $private_key = Mail::DKIM::PrivateKey->load(
        File => $filename,
    );

    die "Could not load DKIM private key.\n"
        unless $private_key;

    print "DKIM private key loaded successfully.\n";

    return $private_key;
}

# ============================================================
# EXTRACT RECIPIENT DOMAIN
# ============================================================

sub get_recipient_domain {

    my ($email) = @_;

    return unless $email =~ /\@([^\@]+)$/;

    my $domain = lc($1);

    $domain =~ s/\.$//;

    return $domain;
}

# ============================================================
# MX LOOKUP
# ============================================================

sub lookup_mx {

    my ($domain) = @_;

    print "\n";
    print "========================================\n";
    print "MX LOOKUP\n";
    print "Domain: $domain\n";
    print "========================================\n";

    # IMPORTANT:
    # Correct Net::DNS API:
    # Net::DNS::mx($resolver, $domain)
    my @mx = Net::DNS::mx(
        $resolver,
        $domain,
    );

    die "No MX records found for $domain\n"
        unless @mx;

    print "\nMX records returned by DNS:\n";

    foreach my $rr (@mx) {

        my $preference = $rr->preference;
        my $exchange   = $rr->exchange;

        $exchange =~ s/\.$//;

        print "  Preference: $preference\n";
        print "  Host      : $exchange\n";
        print "\n";
    }

    return @mx;
}

# ============================================================
# LOOKUP MX HOST ADDRESSES
# ============================================================

sub lookup_addresses {

    my ($host) = @_;

    my @ipv6;
    my @ipv4;

    # --------------------------------------------------------
    # AAAA
    # --------------------------------------------------------

    print "AAAA lookup: $host\n";

    my $aaaa = $resolver->query(
        $host,
        "AAAA",
    );

    if ($aaaa) {

        foreach my $rr ($aaaa->answer) {

            next unless $rr->type eq "AAAA";

            push @ipv6, $rr->address;

            print "  IPv6: ", $rr->address, "\n";
        }
    }

    # --------------------------------------------------------
    # A
    # --------------------------------------------------------

    print "A lookup: $host\n";

    my $a = $resolver->query(
        $host,
        "A",
    );

    if ($a) {

        foreach my $rr ($a->answer) {

            next unless $rr->type eq "A";

            push @ipv4, $rr->address;

            print "  IPv4: ", $rr->address, "\n";
        }
    }

    return (
        \@ipv6,
        \@ipv4,
    );
}

# ============================================================
# CREATE MESSAGE
# ============================================================

sub create_message {

    my (
        $to,
        $subject,
        $body,
    ) = @_;

    my $date = strftime(
        "%a, %d %b %Y %H:%M:%S %z",
        localtime,
    );

    my $message_id =
        "<"
        . time()
        . "."
        . int(rand(1000000000))
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

    my (
        $private_key,
        $message,
    ) = @_;

    # SMTP/DKIM requires CRLF
    $message =~ s/\r?\n/\r\n/g;

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
            "Message-ID",
        ],
    );

    $signer->PRINT($message);

    $signer->CLOSE();

    my $signature = $signer->signature;

    die "DKIM signature generation failed.\n"
        unless $signature;

    return $signature->as_string
        . "\r\n"
        . $message;
}

# ============================================================
# CONNECT TO RESOLVED IP
# ============================================================

sub connect_to_ip {

    my (
        $mx_host,
        $ip,
        $family,
    ) = @_;

    my $family_name =
        ($family == AF_INET6)
        ? "IPv6"
        : "IPv4";

    print "\n";
    print "----------------------------------------\n";
    print "MX       : $mx_host\n";
    print "IP       : $ip\n";
    print "Protocol : $family_name\n";
    print "Port     : 25\n";
    print "----------------------------------------\n";

    # --------------------------------------------------------
    # Connect using the already-resolved IP.
    # TLS hostname remains the MX hostname.
    # --------------------------------------------------------

    my $smtp = eval {

        Net::SMTP->new(
            Host    => $ip,
            Port    => $SMTP_PORT,
            Hello   => $HELO_DOMAIN,
            Timeout => 30,
            Family  => $family,
            Debug   => 0,
        );
    };

    unless ($smtp) {

        print "TCP connection failed.\n";

        return;
    }

    print "TCP connection established.\n";

    # --------------------------------------------------------
    # STARTTLS
    # --------------------------------------------------------

    print "Starting STARTTLS...\n";

    my $tls_ok = eval {

        $smtp->starttls(
            SSL_verify_mode => SSL_VERIFY_PEER,
            SSL_hostname    => $mx_host,
        );
    };

    unless ($tls_ok) {

        print "STARTTLS failed.\n";

        eval {
            $smtp->quit();
        };

        return;
    }

    print "TLS connection established.\n";

    # --------------------------------------------------------
    # EHLO AGAIN AFTER STARTTLS
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
# SMTP TRANSACTION
# ============================================================

sub smtp_transaction {

    my (
        $smtp,
        $to,
        $signed_message,
    ) = @_;

    # --------------------------------------------------------
    # MAIL FROM
    # --------------------------------------------------------

    print "MAIL FROM: $FROM\n";

    unless ($smtp->mail($FROM)) {

        print "MAIL FROM rejected.\n";

        return;
    }

    # --------------------------------------------------------
    # RCPT TO
    # --------------------------------------------------------

    print "RCPT TO: $to\n";

    unless ($smtp->to($to)) {

        print "RCPT TO rejected.\n";

        return;
    }

    # --------------------------------------------------------
    # DATA
    # --------------------------------------------------------

    print "DATA...\n";

    unless ($smtp->data()) {

        print "DATA command failed.\n";

        return;
    }

    unless ($smtp->datasend($signed_message)) {

        print "Message data transmission failed.\n";

        return;
    }

    unless ($smtp->dataend()) {

        print "DATA END failed.\n";

        return;
    }

    return 1;
}

# ============================================================
# TRY ONE MX
# ============================================================

sub try_mx {

    my (
        $mx_host,
        $ipv6,
        $ipv4,
        $to,
        $signed_message,
    ) = @_;

    # ========================================================
    # IPv6 FIRST
    # ========================================================

    foreach my $ip (@$ipv6) {

        my $smtp = connect_to_ip(
            $mx_host,
            $ip,
            AF_INET6,
        );

        next unless $smtp;

        if (
            smtp_transaction(
                $smtp,
                $to,
                $signed_message,
            )
        ) {

            print "\n";
            print "========================================\n";
            print "MESSAGE ACCEPTED\n";
            print "========================================\n";
            print "MX       : $mx_host\n";
            print "IP       : $ip\n";
            print "Protocol : IPv6\n";
            print "TLS      : STARTTLS\n";
            print "DKIM     : YES\n";
            print "========================================\n";

            eval {
                $smtp->quit();
            };

            return 1;
        }

        eval {
            $smtp->quit();
        };
    }

    # ========================================================
    # IPv4 FALLBACK
    # ========================================================

    foreach my $ip (@$ipv4) {

        my $smtp = connect_to_ip(
            $mx_host,
            $ip,
            AF_INET,
        );

        next unless $smtp;

        if (
            smtp_transaction(
                $smtp,
                $to,
                $signed_message,
            )
        ) {

            print "\n";
            print "========================================\n";
            print "MESSAGE ACCEPTED\n";
            print "========================================\n";
            print "MX       : $mx_host\n";
            print "IP       : $ip\n";
            print "Protocol : IPv4\n";
            print "TLS      : STARTTLS\n";
            print "DKIM     : YES\n";
            print "========================================\n";

            eval {
                $smtp->quit();
            };

            return 1;
        }

        eval {
            $smtp->quit();
        };
    }

    return;
}

# ============================================================
# SEND MAIL
# ============================================================

sub send_mail {

    my (
        $to,
        $subject,
        $body,
        $private_key,
    ) = @_;

    my $recipient_domain =
        get_recipient_domain($to);

    die "Could not determine recipient domain.\n"
        unless $recipient_domain;

    print "\n";
    print "Recipient: $to\n";
    print "Domain   : $recipient_domain\n";

    # --------------------------------------------------------
    # MX LOOKUP
    # --------------------------------------------------------

    my @mx_records =
        lookup_mx($recipient_domain);

    # --------------------------------------------------------
    # CREATE MESSAGE
    # --------------------------------------------------------

    my $message = create_message(
        $to,
        $subject,
        $body,
    );

    # --------------------------------------------------------
    # DKIM
    # --------------------------------------------------------

    print "\nGenerating DKIM signature...\n";

    my $signed_message =
        sign_message(
            $private_key,
            $message,
        );

    print "DKIM signature generated.\n";

    # --------------------------------------------------------
    # MX LOOP
    # --------------------------------------------------------

    foreach my $mx (@mx_records) {

        my $preference =
            $mx->preference;

        my $mx_host =
            $mx->exchange;

        $mx_host =~ s/\.$//;

        print "\n";
        print "========================================\n";
        print "TRYING MX\n";
        print "Preference : $preference\n";
        print "Hostname   : $mx_host\n";
        print "========================================\n";

        # ----------------------------------------------------
        # Resolve MX HOST -> AAAA + A
        # ----------------------------------------------------

        my (
            $ipv6,
            $ipv4,
        ) = lookup_addresses($mx_host);

        unless (@$ipv6 || @$ipv4) {

            print "No A/AAAA records for this MX.\n";

            next;
        }

        # ----------------------------------------------------
        # Connect + STARTTLS + SMTP
        # ----------------------------------------------------

        if (
            try_mx(
                $mx_host,
                $ipv6,
                $ipv4,
                $to,
                $signed_message,
            )
        ) {

            return 1;
        }

        print "\nMX failed: $mx_host\n";
        print "Trying next MX...\n";
    }

    die "\nAll MX servers/addresses failed.\n";
}

# ============================================================
# LOAD DKIM
# ============================================================

my $dkim_key =
    load_dkim_key();

# ============================================================
# START
# ============================================================

print "\n";
print "========================================\n";
print "DIRECT MX SMTP SENDER\n";
print "========================================\n";
print "From      : $FROM\n";
print "Domain    : $DOMAIN\n";
print "MX        : AUTOMATIC\n";
print "IPv6      : FIRST\n";
print "IPv4      : FALLBACK\n";
print "STARTTLS  : REQUIRED\n";
print "DKIM      : ENABLED\n";
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
    # Validate email
    # --------------------------------------------------------

    unless (
        $to =~ /^[A-Za-z0-9.!#\$%&'*+\/=?^_`{|}~-]+\@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/
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

    # Prevent header injection
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
            $dkim_key,
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
