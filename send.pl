#!/usr/bin/perl

use strict;
use warnings;

use Net::SMTP;
use Net::DNS;
use Socket qw(AF_INET AF_INET6);
use LWP::UserAgent;
use IO::Socket::SSL qw(SSL_VERIFY_PEER);

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
my $HELO_DOMAIN = $DOMAIN;

my $SMTP_PORT   = 25;
my $TIMEOUT     = 30;

# IMPORTANT:
# Do NOT use the previously exposed public private-key URL.
# Put your NEW rotated private-key URL here.
my $KEY_URL = "https://raw.githubusercontent.com/mosesbr88/perl-smtp/refs/heads/main/pvt.txt";

# Require STARTTLS.
my $REQUIRE_STARTTLS = 1;

# Verify TLS certificate.
my $VERIFY_TLS = 1;

# ============================================================
# DNS RESOLVER
# ============================================================

my $resolver = Net::DNS::Resolver->new(
    udp_timeout => 5,
    tcp_timeout => 10,
    retry       => 2,
);

# ============================================================
# LOAD DKIM PRIVATE KEY
# ============================================================

sub load_dkim_key {

    print "[DKIM] Downloading private key...\n";

    my $ua = LWP::UserAgent->new(
        timeout => 20,
        agent   => "Perl-Direct-SMTP/1.0",
    );

    my $response = $ua->get($KEY_URL);

    die "[DKIM] Failed to download private key: "
        . $response->status_line . "\n"
        unless $response->is_success;

    my $pem = $response->decoded_content;

    die "[DKIM] Downloaded key does not look like a PEM private key\n"
        unless $pem =~ /-----BEGIN .*PRIVATE KEY-----/;

    my ($fh, $filename) = tempfile(
        "dkim-key-XXXXXX",
        SUFFIX => ".pem",
        UNLINK => 1
    );

    binmode($fh);

    print $fh $pem
        or die "[DKIM] Cannot write temporary key file: $!\n";

    close($fh)
        or die "[DKIM] Cannot close temporary key file: $!\n";

    my $key;

    eval {
        $key = Mail::DKIM::PrivateKey->load(
            File => $filename
        );
    };

    if ($@ || !$key) {
        die "[DKIM] Could not load private key:\n$@\n";
    }

    print "[DKIM] Private key loaded successfully.\n";

    return $key;
}

# ============================================================
# EXTRACT DOMAIN FROM EMAIL
# ============================================================

sub get_recipient_domain {

    my ($email) = @_;

    $email =~ s/^\s+//;
    $email =~ s/\s+$//;

    die "[SMTP] Invalid recipient email address.\n"
        unless $email =~ /^[^@\s]+@([^@\s]+)$/;

    my $domain = lc($1);

    $domain =~ s/\.$//;

    return $domain;
}

# ============================================================
# MX LOOKUP
#
# IMPORTANT:
# We intentionally DO NOT use:
#
#   $resolver->mx(...)
#
# Instead we use the documented Resolver->query(..., "MX")
# API and inspect MX records manually.
# ============================================================

sub lookup_mx {

    my ($domain) = @_;

    print "\n[DNS] Looking up MX for: $domain\n";

    my $packet = $resolver->query(
        $domain,
        "MX"
    );

    if (!$packet) {

        print "[DNS] MX query failed: "
            . $resolver->errorstring . "\n";

        return ();
    }

    my @mx_records;

    foreach my $rr ($packet->answer) {

        # Never assume an RR is MX.
        next unless $rr->type eq "MX";

        my $preference = $rr->preference;
        my $exchange   = $rr->exchange;

        $exchange =~ s/\.$//;

        push @mx_records, {
            preference => $preference,
            host       => $exchange,
        };
    }

    # Lowest MX preference first.
    @mx_records = sort {
        $a->{preference} <=> $b->{preference}
    } @mx_records;

    if (!@mx_records) {

        print "[DNS] No MX records found.\n";

        return ();
    }

    foreach my $mx (@mx_records) {

        print sprintf(
            "[MX] Preference=%s Host=%s\n",
            $mx->{preference},
            $mx->{host}
        );
    }

    return @mx_records;
}

# ============================================================
# ADDRESS LOOKUP
#
# IPv6 first, then IPv4.
# ============================================================

sub lookup_addresses {

    my ($host) = @_;

    my @ipv6;
    my @ipv4;

    print "[DNS] Resolving AAAA for $host...\n";

    my $aaaa_packet = $resolver->query(
        $host,
        "AAAA"
    );

    if ($aaaa_packet) {

        foreach my $rr ($aaaa_packet->answer) {

            next unless $rr->type eq "AAAA";

            my $ip = $rr->address;

            push @ipv6, $ip;

            print "[AAAA] $ip\n";
        }
    }
    else {

        print "[DNS] AAAA lookup failed: "
            . $resolver->errorstring . "\n";
    }

    print "[DNS] Resolving A for $host...\n";

    my $a_packet = $resolver->query(
        $host,
        "A"
    );

    if ($a_packet) {

        foreach my $rr ($a_packet->answer) {

            next unless $rr->type eq "A";

            my $ip = $rr->address;

            push @ipv4, $ip;

            print "[A] $ip\n";
        }
    }
    else {

        print "[DNS] A lookup failed: "
            . $resolver->errorstring . "\n";
    }

    return (\@ipv6, \@ipv4);
}

# ============================================================
# FALLBACK A/AAAA LOOKUP
#
# Used when a domain has no MX record.
# ============================================================

sub lookup_domain_addresses {

    my ($domain) = @_;

    print "\n[DNS] No MX found. Trying domain addresses...\n";

    my ($ipv6, $ipv4) = lookup_addresses($domain);

    return ($ipv6, $ipv4);
}

# ============================================================
# CREATE EMAIL
# ============================================================

sub create_message {

    my ($to, $subject, $body) = @_;

    my $date = strftime(
        "%a, %d %b %Y %H:%M:%S %z",
        localtime
    );

    my $random = int(rand(900000)) + 100000;

    my $message_id =
        "<"
        . time()
        . "."
        . $random
        . "\@$DOMAIN>";

    # CRLF is required for SMTP/DKIM.
    my $message =
          "From: $FROM\r\n"
        . "To: $to\r\n"
        . "Subject: $subject\r\n"
        . "Date: $date\r\n"
        . "Message-ID: $message_id\r\n"
        . "MIME-Version: 1.0\r\n"
        . "Content-Type: text/plain; charset=UTF-8\r\n"
        . "Content-Transfer-Encoding: 8bit\r\n"
        . "\r\n"
        . $body
        . "\r\n";

    return $message;
}

# ============================================================
# DKIM SIGN
# ============================================================

sub sign_message {

    my ($message, $private_key) = @_;

    print "[DKIM] Signing message...\n";

    my $dkim = Mail::DKIM::Signer->new(

        Algorithm => "rsa-sha256",

        Method => "relaxed",

        Domain => $DOMAIN,

        Selector => $SELECTOR,

        Key => $private_key,

        Headers => join(
            ":",
            qw(
                From
                To
                Subject
                Date
                Message-ID
            )
        ),
    );

    # Feed message using SMTP CRLF.
    my @lines = split(/\r\n/, $message, -1);

    foreach my $line (@lines) {

        $dkim->PRINT(
            $line . "\r\n"
        );
    }

    $dkim->CLOSE;

    my $signature = $dkim->signature;

    die "[DKIM] Signature generation failed.\n"
        unless $signature;

    my $dkim_header = $signature->as_string;

    # Mail::DKIM::TextWrap formats the signature nicely.
    $dkim_header =~ s/\r?\n/\r\n/g;

    print "[DKIM] Signature generated successfully.\n";

    return $dkim_header . "\r\n" . $message;
}

# ============================================================
# CONNECT TO SMTP SERVER
# ============================================================

sub connect_to_smtp {

    my ($ip, $family, $mx_host) = @_;

    my $family_name =
        ($family == AF_INET6)
        ? "IPv6"
        : "IPv4";

    print "\n[SMTP] Connecting to $ip:$SMTP_PORT ($family_name)\n";

    my $smtp;

    eval {

        $smtp = Net::SMTP->new(

            Host => $ip,

            Port => $SMTP_PORT,

            Hello => $HELO_DOMAIN,

            Timeout => $TIMEOUT,

            Family => $family,
        );
    };

    if ($@ || !$smtp) {

        print "[SMTP] Connection failed: "
            . ($@ || "unknown error")
            . "\n";

        return undef;
    }

    print "[SMTP] Connected.\n";

    # --------------------------------------------------------
    # STARTTLS
    # --------------------------------------------------------

    print "[TLS] Checking STARTTLS...\n";

    my $tls_ok = 0;

    eval {

        if ($VERIFY_TLS) {

            $tls_ok = $smtp->starttls(

                SSL_verify_mode => SSL_VERIFY_PEER,

                SSL_hostname => $mx_host,
            );
        }
        else {

            $tls_ok = $smtp->starttls(

                SSL_verify_mode => 0,

                SSL_hostname => $mx_host,
            );
        }
    };

    if ($@) {

        print "[TLS] STARTTLS error: $@\n";

        eval {
            $smtp->quit;
        };

        return undef;
    }

    if (!$tls_ok) {

        print "[TLS] STARTTLS failed.\n";

        eval {
            $smtp->quit;
        };

        return undef
            if $REQUIRE_STARTTLS;
    }
    else {

        print "[TLS] STARTTLS successful.\n";
    }

    # --------------------------------------------------------
    # EHLO AFTER STARTTLS
    # --------------------------------------------------------

    if ($tls_ok) {

        my $hello_ok = eval {
            $smtp->hello($HELO_DOMAIN);
        };

        if (!$hello_ok) {

            print "[SMTP] EHLO after STARTTLS failed.\n";

            eval {
                $smtp->quit;
            };

            return undef;
        }

        print "[SMTP] EHLO after TLS successful.\n";
    }

    return $smtp;
}

# ============================================================
# SMTP TRANSACTION
# ============================================================

sub smtp_transaction {

    my ($smtp, $to, $message) = @_;

    print "[SMTP] MAIL FROM <$FROM>\n";

    unless ($smtp->mail($FROM)) {

        print "[SMTP] MAIL FROM rejected.\n";

        return 0;
    }

    print "[SMTP] RCPT TO <$to>\n";

    unless ($smtp->to($to)) {

        print "[SMTP] RCPT TO rejected.\n";

        return 0;
    }

    print "[SMTP] Sending DATA...\n";

    unless ($smtp->data()) {

        print "[SMTP] DATA command rejected.\n";

        return 0;
    }

    unless ($smtp->datasend($message)) {

        print "[SMTP] Failed while sending message data.\n";

        return 0;
    }

    unless ($smtp->dataend()) {

        print "[SMTP] Message rejected after DATA.\n";

        return 0;
    }

    print "[SMTP] Message accepted by remote MX.\n";

    return 1;
}

# ============================================================
# TRY ONE MX HOST
# ============================================================

sub try_mx {

    my ($mx_host, $to, $message) = @_;

    print "\n====================================================\n";
    print "[MX] Trying: $mx_host\n";
    print "====================================================\n";

    my ($ipv6, $ipv4) = lookup_addresses($mx_host);

    # --------------------------------------------------------
    # IPv6 FIRST
    # --------------------------------------------------------

    foreach my $ip (@$ipv6) {

        print "\n[TRY] IPv6 $ip\n";

        my $smtp = connect_to_smtp(
            $ip,
            AF_INET6,
            $mx_host
        );

        next unless $smtp;

        my $ok = smtp_transaction(
            $smtp,
            $to,
            $message
        );

        eval {
            $smtp->quit;
        };

        return 1 if $ok;
    }

    # --------------------------------------------------------
    # IPv4 SECOND
    # --------------------------------------------------------

    foreach my $ip (@$ipv4) {

        print "\n[TRY] IPv4 $ip\n";

        my $smtp = connect_to_smtp(
            $ip,
            AF_INET,
            $mx_host
        );

        next unless $smtp;

        my $ok = smtp_transaction(
            $smtp,
            $to,
            $message
        );

        eval {
            $smtp->quit;
        };

        return 1 if $ok;
    }

    print "[MX] All addresses failed for $mx_host\n";

    return 0;
}

# ============================================================
# SEND MAIL
# ============================================================

sub send_mail {

    my ($to, $subject, $body, $private_key) = @_;

    my $domain = get_recipient_domain($to);

    print "\n====================================================\n";
    print "[MAIL] Recipient : $to\n";
    print "[MAIL] Domain    : $domain\n";
    print "====================================================\n";

    # --------------------------------------------------------
    # CREATE + DKIM SIGN
    # --------------------------------------------------------

    my $unsigned_message = create_message(
        $to,
        $subject,
        $body
    );

    my $message = sign_message(
        $unsigned_message,
        $private_key
    );

    # --------------------------------------------------------
    # MX LOOKUP
    # --------------------------------------------------------

    my @mx_records = lookup_mx($domain);

    # --------------------------------------------------------
    # NORMAL MX DELIVERY
    # --------------------------------------------------------

    if (@mx_records) {

        foreach my $mx (@mx_records) {

            my $mx_host = $mx->{host};

            print "\n[DELIVERY] MX: $mx_host\n";

            if (try_mx(
                $mx_host,
                $to,
                $message
            )) {

                print "\n[SUCCESS] Mail delivered to MX.\n";

                return 1;
            }
        }

        print "\n[FAIL] All MX servers failed.\n";

        return 0;
    }

    # --------------------------------------------------------
    # NO MX FALLBACK
    # --------------------------------------------------------

    my ($ipv6, $ipv4) =
        lookup_domain_addresses($domain);

    # IPv6 first.
    foreach my $ip (@$ipv6) {

        print "\n[FALLBACK] Trying IPv6 $ip\n";

        my $smtp = connect_to_smtp(
            $ip,
            AF_INET6,
            $domain
        );

        next unless $smtp;

        my $ok = smtp_transaction(
            $smtp,
            $to,
            $message
        );

        eval {
            $smtp->quit;
        };

        return 1 if $ok;
    }

    # IPv4 second.
    foreach my $ip (@$ipv4) {

        print "\n[FALLBACK] Trying IPv4 $ip\n";

        my $smtp = connect_to_smtp(
            $ip,
            AF_INET,
            $domain
        );

        next unless $smtp;

        my $ok = smtp_transaction(
            $smtp,
            $to,
            $message
        );

        eval {
            $smtp->quit;
        };

        return 1 if $ok;
    }

    print "\n[FAIL] Could not connect to destination domain.\n";

    return 0;
}

# ============================================================
# STARTUP
# ============================================================

print "====================================================\n";
print " Direct SMTP Sender - Perl\n";
print " Domain : $DOMAIN\n";
print " From   : $FROM\n";
print " IPv6   : enabled\n";
print " IPv4   : enabled\n";
print " TLS    : STARTTLS required\n";
print " DKIM   : RSA-SHA256\n";
print "====================================================\n";

# ------------------------------------------------------------
# LOAD PRIVATE KEY ONCE
# ------------------------------------------------------------

my $private_key = load_dkim_key();

# ============================================================
# INTERACTIVE LOOP
# ============================================================

while (1) {

    print "\nReceiver email (or 'exit'): ";

    my $to = <STDIN>;

    last unless defined $to;

    chomp($to);

    $to =~ s/^\s+//;
    $to =~ s/\s+$//;

    last if lc($to) eq "exit";

    unless ($to =~ /^[^@\s]+@[^@\s]+$/) {

        print "[ERROR] Invalid email address.\n";

        next;
    }

    print "Subject: ";

    my $subject = <STDIN>;

    last unless defined $subject;

    chomp($subject);

    print "Body: ";

    my $body = <STDIN>;

    last unless defined $body;

    chomp($body);

    eval {

        my $success = send_mail(
            $to,
            $subject,
            $body,
            $private_key
        );

        if ($success) {

            print "\n====================================================\n";
            print "SUCCESS\n";
            print "====================================================\n";
        }
        else {

            print "\n====================================================\n";
            print "FAILED\n";
            print "====================================================\n";
        }
    };

    if ($@) {

        print "\n[ERROR]\n";
        print $@;
        print "\n";
    }
}

print "\nExiting.\n";
