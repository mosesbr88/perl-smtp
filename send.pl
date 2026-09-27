#!/usr/bin/perl

use strict;
use warnings;

# ============================================================
# DNS
# ============================================================
use Net::DNS;

# ============================================================
# NETWORK / SOCKET
# ============================================================
use Socket qw(
    AF_INET
    AF_INET6
    SOCK_STREAM
    SOL_SOCKET
    SO_KEEPALIVE
    inet_pton
    pack_sockaddr_in
    pack_sockaddr_in6
);

# ============================================================
# TLS
# ============================================================
use IO::Socket::SSL qw(
    SSL_VERIFY_PEER
    SSL_VERIFY_NONE
);

# ============================================================
# HTTP / DKIM
# ============================================================
use LWP::UserAgent;
use Mail::DKIM::Signer;
use Mail::DKIM::PrivateKey;

# ============================================================
# FILE / TIME
# ============================================================
use File::Temp qw(tempfile);
use POSIX qw(strftime);

# ============================================================
# CONFIG
# ============================================================

my $DOMAIN      = "sujoy-z.us.to";
my $FROM        = "test\@$DOMAIN";
my $SELECTOR    = "default";
my $HELO_DOMAIN = $DOMAIN;

my $SMTP_PORT = 25;

# Connection timeout.
my $CONNECT_TIMEOUT = 30;

# SMTP response timeout.
my $READ_TIMEOUT = 30;

# Require STARTTLS.
my $REQUIRE_STARTTLS = 1;

# Verify remote TLS certificate.
my $VERIFY_TLS = 1;

# ------------------------------------------------------------
# PUT YOUR NEW / ROTATED DKIM PRIVATE KEY URL HERE.
#
# DO NOT use the previously exposed pvt.txt key.
# ------------------------------------------------------------

my $KEY_URL = "https://raw.githubusercontent.com/mosesbr88/perl-smtp/refs/heads/main/pvt.txt";

# ============================================================
# DNS RESOLVER
# ============================================================

my $resolver = Net::DNS::Resolver->new(
    udp_timeout => 5,
    tcp_timeout => 10,
    retry       => 2,
);

# ============================================================
# UTILITY: PRINT ERROR
# ============================================================

sub error_text {
    my ($prefix) = @_;

    my $dns_error = eval {
        $resolver->errorstring
    };

    $dns_error = "" unless defined $dns_error;

    return "$prefix $dns_error";
}

# ============================================================
# LOAD DKIM PRIVATE KEY
# ============================================================

sub load_dkim_key {

    die "[DKIM] KEY_URL is still a placeholder.\n"
        if !defined($KEY_URL)
        || $KEY_URL eq ""
        || $KEY_URL eq "YOUR_NEW_PRIVATE_KEY_URL";

    print "[DKIM] Downloading private key...\n";

    my $ua = LWP::UserAgent->new(
        timeout => 20,
        agent   => "Perl-Direct-SMTP/2.0",
    );

    my $response = $ua->get($KEY_URL);

    unless ($response->is_success) {

        die "[DKIM] Private key download failed: "
            . $response->status_line
            . "\n";
    }

    my $pem = $response->decoded_content;

    unless (
        $pem =~ /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/
    ) {
        die "[DKIM] Downloaded file does not contain a PEM private key.\n";
    }

    my ($fh, $filename) = tempfile(
        "dkim-key-XXXXXX",
        SUFFIX => ".pem",
        UNLINK => 1,
    );

    binmode($fh);

    print $fh $pem
        or die "[DKIM] Failed writing temporary private key: $!\n";

    close($fh)
        or die "[DKIM] Failed closing temporary private key: $!\n";

    chmod 0600, $filename;

    my $key;

    eval {
        $key = Mail::DKIM::PrivateKey->load(
            File => $filename
        );
    };

    if ($@ || !$key) {

        my $e = $@ || "unknown error";

        die "[DKIM] Private key could not be loaded:\n$e\n";
    }

    print "[DKIM] Private key loaded successfully.\n";

    return $key;
}

# ============================================================
# EMAIL VALIDATION
# ============================================================

sub normalize_email {

    my ($email) = @_;

    $email = "" unless defined $email;

    $email =~ s/^\s+//;
    $email =~ s/\s+$//;

    return $email;
}

sub get_recipient_domain {

    my ($email) = @_;

    $email = normalize_email($email);

    unless (
        $email =~
        /^[A-Za-z0-9.!#\$%&'*+\/=?^_`{|}~-]+\@([A-Za-z0-9.-]+)$/
    ) {
        die "[MAIL] Invalid recipient email address.\n";
    }

    my $domain = lc($1);

    $domain =~ s/\.$//;

    unless (
        $domain =~
        /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/
    ) {
        die "[DNS] Invalid recipient domain: $domain\n";
    }

    return $domain;
}

# ============================================================
# DNS: MX LOOKUP
#
# IMPORTANT:
# We do NOT use:
#
#   $resolver->mx(...)
#
# Instead:
#
#   $resolver->query($domain, "MX")
#
# ============================================================

sub lookup_mx {

    my ($domain) = @_;

    print "\n[DNS] MX lookup: $domain\n";

    my $packet;

    eval {
        $packet = $resolver->query(
            $domain,
            "MX"
        );
    };

    if ($@) {

        print "[DNS] MX query exception: $@\n";

        return ();
    }

    unless ($packet) {

        print "[DNS] MX query failed: "
            . $resolver->errorstring
            . "\n";

        return ();
    }

    my @records;

    foreach my $rr ($packet->answer) {

        next unless $rr->type eq "MX";

        my $preference = $rr->preference;
        my $exchange   = $rr->exchange;

        $exchange =~ s/\.$//;

        next unless $exchange;

        push @records, {
            preference => 0 + $preference,
            host       => lc($exchange),
        };
    }

    # Lowest preference first.
    @records = sort {
        $a->{preference} <=> $b->{preference}
    } @records;

    if (!@records) {

        print "[DNS] No MX records found.\n";

        return ();
    }

    print "[DNS] MX records:\n";

    foreach my $mx (@records) {

        print "       "
            . $mx->{preference}
            . " "
            . $mx->{host}
            . "\n";
    }

    return @records;
}

# ============================================================
# DNS: A / AAAA LOOKUP
# ============================================================

sub lookup_addresses {

    my ($hostname) = @_;

    my @ipv6;
    my @ipv4;

    # --------------------------------------------------------
    # AAAA
    # --------------------------------------------------------

    print "[DNS] AAAA lookup: $hostname\n";

    my $aaaa;

    eval {
        $aaaa = $resolver->query(
            $hostname,
            "AAAA"
        );
    };

    if ($aaaa) {

        foreach my $rr ($aaaa->answer) {

            next unless $rr->type eq "AAAA";

            my $ip = $rr->address;

            next unless defined $ip && length $ip;

            push @ipv6, $ip;
        }
    }

    foreach my $ip (@ipv6) {

        print "       IPv6 $ip\n";
    }

    # --------------------------------------------------------
    # A
    # --------------------------------------------------------

    print "[DNS] A lookup: $hostname\n";

    my $a;

    eval {
        $a = $resolver->query(
            $hostname,
            "A"
        );
    };

    if ($a) {

        foreach my $rr ($a->answer) {

            next unless $rr->type eq "A";

            my $ip = $rr->address;

            next unless defined $ip && length $ip;

            push @ipv4, $ip;
        }
    }

    foreach my $ip (@ipv4) {

        print "       IPv4 $ip\n";
    }

    return (\@ipv6, \@ipv4);
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

    # Remove bare CR/LF from subject.
    $subject =~ s/[\r\n]+/ /g;

    # Prevent SMTP header injection.
    $to =~ s/[\r\n]+//g;

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

    print "[DKIM] Creating DKIM signature...\n";

    my $dkim;

    eval {

        $dkim = Mail::DKIM::Signer->new(

            Algorithm => "rsa-sha256",

            Method => "relaxed",

            Domain => $DOMAIN,

            Selector => $SELECTOR,

            Key => $private_key,

            Headers =>
                "From:To:Subject:Date:Message-ID",
        );
    };

    if ($@ || !$dkim) {

        die "[DKIM] Signer creation failed:\n$@\n";
    }

    # Mail::DKIM expects SMTP CRLF input.
    #
    # Do not chomp the CRLF.
    #
    my @lines = split(
        /\r\n/,
        $message,
        -1
    );

    foreach my $line (@lines) {

        $dkim->PRINT(
            $line . "\r\n"
        );
    }

    $dkim->CLOSE;

    my $signature = $dkim->signature;

    die "[DKIM] Signature was not generated.\n"
        unless $signature;

    my $header = $signature->as_string;

    $header =~ s/\r?\n/\r\n/g;

    $header =~ s/\r\n$//;

    print "[DKIM] Signature generated.\n";

    return $header . "\r\n" . $message;
}

# ============================================================
# SOCKET: SET TIMEOUT
# ============================================================

sub set_socket_timeout {

    my ($socket, $timeout) = @_;

    eval {
        $socket->timeout($timeout)
            if $socket->can("timeout");
    };

    return;
}

# ============================================================
# SOCKET: CONNECT IPV4
# ============================================================

sub connect_ipv4 {

    my ($ip, $port) = @_;

    my $sock;

    socket(
        $sock,
        AF_INET,
        SOCK_STREAM,
        0
    )
        or die "socket(AF_INET): $!";

    setsockopt(
        $sock,
        SOL_SOCKET,
        SO_KEEPALIVE,
        pack("I", 1)
    );

    my $addr = inet_pton(
        AF_INET,
        $ip
    );

    die "Invalid IPv4 address: $ip"
        unless $addr;

    my $sockaddr = pack_sockaddr_in(
        $port,
        $addr
    );

    my $connected = eval {

        local $SIG{ALRM} = sub {
            die "connection timeout\n";
        };

        alarm($CONNECT_TIMEOUT);

        my $ok = connect(
            $sock,
            $sockaddr
        );

        alarm(0);

        return $ok;
    };

    alarm(0);

    unless ($connected) {

        close($sock);

        return undef;
    }

    return $sock;
}

# ============================================================
# SOCKET: CONNECT IPV6
# ============================================================

sub connect_ipv6 {

    my ($ip, $port) = @_;

    my $sock;

    socket(
        $sock,
        AF_INET6,
        SOCK_STREAM,
        0
    )
        or die "socket(AF_INET6): $!";

    setsockopt(
        $sock,
        SOL_SOCKET,
        SO_KEEPALIVE,
        pack("I", 1)
    );

    my $addr = inet_pton(
        AF_INET6,
        $ip
    );

    die "Invalid IPv6 address: $ip"
        unless $addr;

    my $sockaddr = pack_sockaddr_in6(
        $port,
        $addr
    );

    my $connected = eval {

        local $SIG{ALRM} = sub {
            die "connection timeout\n";
        };

        alarm($CONNECT_TIMEOUT);

        my $ok = connect(
            $sock,
            $sockaddr
        );

        alarm(0);

        return $ok;
    };

    alarm(0);

    unless ($connected) {

        close($sock);

        return undef;
    }

    return $sock;
}

# ============================================================
# SOCKET: CONNECT
# ============================================================

sub connect_ip {

    my ($ip, $family) = @_;

    if ($family == AF_INET6) {

        return connect_ipv6(
            $ip,
            $SMTP_PORT
        );
    }

    return connect_ipv4(
        $ip,
        $SMTP_PORT
    );
}

# ============================================================
# READ ONE SMTP RESPONSE
#
# Handles:
#
# 220 server...
# 250-server...
# 250 STARTTLS
#
# ============================================================

sub read_smtp_response {

    my ($socket) = @_;

    my @lines;

    while (1) {

        my $line;

        my $read_ok = eval {

            local $SIG{ALRM} = sub {
                die "SMTP read timeout\n";
            };

            alarm($READ_TIMEOUT);

            $line = <$socket>;

            alarm(0);

            return 1;
        };

        alarm(0);

        unless ($read_ok && defined $line) {

            die "[SMTP] Connection closed or read timeout.\n";
        }

        $line =~ s/[\r\n]+$//;

        push @lines, $line;

        print "[S] $line\n";

        # RFC SMTP reply format:
        #
        # 250-foo
        # 250-bar
        # 250 baz
        #
        if ($line =~ /^(\d{3})([\s-])(.*)$/) {

            my $separator = $2;

            if ($separator eq " ") {

                my $code = 0 + $1;

                return (
                    $code,
                    \@lines
                );
            }
        }
    }
}

# ============================================================
# SEND SMTP COMMAND
# ============================================================

sub smtp_command {

    my ($socket, $command) = @_;

    print "[C] $command\n";

    print $socket $command . "\r\n"
        or die "[SMTP] Failed sending command.\n";

    return read_smtp_response($socket);
}

# ============================================================
# CHECK SMTP CODE
# ============================================================

sub require_code {

    my ($code, $expected_ref, $operation) = @_;

    foreach my $expected (@$expected_ref) {

        return 1
            if $code == $expected;
    }

    die "[SMTP] $operation failed with SMTP code $code\n";
}

# ============================================================
# EHLO + CAPABILITIES
# ============================================================

sub smtp_ehlo {

    my ($socket) = @_;

    my ($code, $lines) =
        smtp_command(
            $socket,
            "EHLO $HELO_DOMAIN"
        );

    require_code(
        $code,
        [250],
        "EHLO"
    );

    my %caps;

    foreach my $line (@$lines) {

        # Example:
        #
        # 250-STARTTLS
        # 250-SIZE 52428800
        # 250 SMTPUTF8
        #

        if ($line =~ /^\d{3}[- ]([A-Za-z0-9][A-Za-z0-9-]*)\b(.*)$/) {

            my $name = uc($1);

            $caps{$name} = 1;
        }
    }

    return \%caps;
}

# ============================================================
# STARTTLS
# ============================================================

sub smtp_starttls {

    my ($socket, $mx_host) = @_;

    print "[TLS] Requesting STARTTLS...\n";

    my ($code, $lines) =
        smtp_command(
            $socket,
            "STARTTLS"
        );

    unless ($code == 220) {

        die "[TLS] STARTTLS rejected by $mx_host "
            . "(SMTP code $code)\n";
    }

    print "[TLS] Server accepted STARTTLS.\n";
    print "[TLS] Starting TLS handshake...\n";

    my $ssl_socket;

    eval {

        if ($VERIFY_TLS) {

            $ssl_socket =
                IO::Socket::SSL->start_SSL(
                    $socket,

                    SSL_hostname =>
                        $mx_host,

                    SSL_verify_mode =>
                        SSL_VERIFY_PEER,

                    Timeout =>
                        $CONNECT_TIMEOUT,
                );
        }
        else {

            $ssl_socket =
                IO::Socket::SSL->start_SSL(
                    $socket,

                    SSL_hostname =>
                        $mx_host,

                    SSL_verify_mode =>
                        SSL_VERIFY_NONE,

                    Timeout =>
                        $CONNECT_TIMEOUT,
                );
        }
    };

    if ($@ || !$ssl_socket) {

        my $ssl_error =
            eval { IO::Socket::SSL::errstr() }
            || $@
            || "unknown TLS error";

        die "[TLS] TLS handshake failed for "
            . "$mx_host: $ssl_error\n";
    }

    $ssl_socket->autoflush(1);

    print "[TLS] TLS handshake successful.\n";

    return $ssl_socket;
}

# ============================================================
# SMTP SESSION
# ============================================================

sub smtp_session {

    my ($ip, $family, $mx_host, $to, $message) = @_;

    my $family_name =
        $family == AF_INET6
        ? "IPv6"
        : "IPv4";

    print "\n----------------------------------------------------\n";
    print "[CONNECT] $mx_host\n";
    print "[CONNECT] $ip ($family_name):$SMTP_PORT\n";
    print "----------------------------------------------------\n";

    my $socket;

    eval {

        $socket = connect_ip(
            $ip,
            $family
        );
    };

    if ($@ || !$socket) {

        print "[CONNECT] Failed: "
            . ($@ || "connection failed")
            . "\n";

        return 0;
    }

    $socket->autoflush(1);

    print "[CONNECT] TCP connection successful.\n";

    # --------------------------------------------------------
    # GREETING
    # --------------------------------------------------------

    my ($greeting_code);

    eval {

        ($greeting_code) =
            read_smtp_response(
                $socket
            );
    };

    if ($@) {

        print "[SMTP] Greeting failed: $@\n";

        close($socket);

        return 0;
    }

    unless ($greeting_code == 220) {

        print "[SMTP] Server greeting rejected: "
            . "$greeting_code\n";

        close($socket);

        return 0;
    }

    # --------------------------------------------------------
    # EHLO
    # --------------------------------------------------------

    my $caps;

    eval {

        $caps = smtp_ehlo(
            $socket
        );
    };

    if ($@) {

        print "[SMTP] EHLO failed: $@\n";

        eval {
            close($socket);
        };

        return 0;
    }

    # --------------------------------------------------------
    # STARTTLS
    # --------------------------------------------------------

    unless ($caps->{STARTTLS}) {

        print "[TLS] $mx_host does NOT advertise STARTTLS.\n";

        if ($REQUIRE_STARTTLS) {

            print "[TLS] Skipping this server because TLS is required.\n";

            close($socket);

            return 0;
        }
    }

    if ($caps->{STARTTLS}) {

        eval {

            $socket = smtp_starttls(
                $socket,
                $mx_host
            );
        };

        if ($@ || !$socket) {

            print "[TLS] Failed: "
                . ($@ || "unknown error")
                . "\n";

            eval {
                close($socket);
            };

            return 0;
        }

        # ----------------------------------------------------
        # RFC 3207:
        # EHLO must be sent again after STARTTLS.
        # ----------------------------------------------------

        eval {

            $caps = smtp_ehlo(
                $socket
            );
        };

        if ($@) {

            print "[SMTP] EHLO after STARTTLS failed: $@\n";

            eval {
                close($socket);
            };

            return 0;
        }

        print "[TLS] Secure SMTP session established.\n";
    }

    # --------------------------------------------------------
    # MAIL FROM
    # --------------------------------------------------------

    my ($code);

    eval {

        ($code) =
            smtp_command(
                $socket,
                "MAIL FROM:<$FROM>"
            );
    };

    if ($@) {

        print "[SMTP] MAIL FROM error: $@\n";

        close($socket);

        return 0;
    }

    unless ($code == 250) {

        print "[SMTP] MAIL FROM rejected: $code\n";

        close($socket);

        return 0;
    }

    # --------------------------------------------------------
    # RCPT TO
    # --------------------------------------------------------

    eval {

        ($code) =
            smtp_command(
                $socket,
                "RCPT TO:<$to>"
            );
    };

    if ($@) {

        print "[SMTP] RCPT TO error: $@\n";

        close($socket);

        return 0;
    }

    unless (
        $code == 250 ||
        $code == 251
    ) {

        print "[SMTP] RCPT TO rejected: $code\n";

        close($socket);

        return 0;
    }

    # --------------------------------------------------------
    # DATA
    # --------------------------------------------------------

    eval {

        ($code) =
            smtp_command(
                $socket,
                "DATA"
            );
    };

    if ($@) {

        print "[SMTP] DATA command failed: $@\n";

        close($socket);

        return 0;
    }

    unless ($code == 354) {

        print "[SMTP] DATA rejected: $code\n";

        close($socket);

        return 0;
    }

    # --------------------------------------------------------
    # SMTP DOT-STUFFING
    #
    # A line beginning with "." must become ".."
    # --------------------------------------------------------

    my @message_lines =
        split(
            /\r\n/,
            $message,
            -1
        );

    foreach my $line (@message_lines) {

        $line =~ s/^\./../;

        print $socket $line . "\r\n"
            or die "[SMTP] Message transmission failed.\n";
    }

    # End DATA with <CRLF>.<CRLF>
    print $socket ".\r\n"
        or die "[SMTP] Failed ending DATA.\n";

    print "[C] <message data>\n";
    print "[C] .\n";

    my ($final_code, $final_lines) =
        read_smtp_response(
            $socket
        );

    unless ($final_code == 250) {

        print "[SMTP] Remote server rejected message: "
            . "$final_code\n";

        eval {
            close($socket);
        };

        return 0;
    }

    print "[SMTP] Remote server accepted message.\n";

    # --------------------------------------------------------
    # QUIT
    # --------------------------------------------------------

    eval {

        smtp_command(
            $socket,
            "QUIT"
        );
    };

    close($socket);

    return 1;
}

# ============================================================
# TRY ALL ADDRESSES FOR ONE MX
# ============================================================

sub try_mx {

    my ($mx_host, $to, $message) = @_;

    print "\n====================================================\n";
    print "[MX] $mx_host\n";
    print "====================================================\n";

    my ($ipv6, $ipv4) =
        lookup_addresses($mx_host);

    # --------------------------------------------------------
    # IPv6
    # --------------------------------------------------------

    foreach my $ip (@$ipv6) {

        print "\n[TRY] IPv6 $ip\n";

        my $ok;

        eval {

            $ok = smtp_session(
                $ip,
                AF_INET6,
                $mx_host,
                $to,
                $message
            );
        };

        if ($@) {

            print "[TRY] IPv6 error: $@\n";

            $ok = 0;
        }

        return 1 if $ok;
    }

    # --------------------------------------------------------
    # IPv4
    # --------------------------------------------------------

    foreach my $ip (@$ipv4) {

        print "\n[TRY] IPv4 $ip\n";

        my $ok;

        eval {

            $ok = smtp_session(
                $ip,
                AF_INET,
                $mx_host,
                $to,
                $message
            );
        };

        if ($@) {

            print "[TRY] IPv4 error: $@\n";

            $ok = 0;
        }

        return 1 if $ok;
    }

    print "\n[MX] All addresses failed for $mx_host\n";

    return 0;
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

    my $domain =
        get_recipient_domain($to);

    print "\n====================================================\n";
    print "[MAIL] From      : $FROM\n";
    print "[MAIL] To        : $to\n";
    print "[MAIL] Domain    : $domain\n";
    print "[MAIL] MX port   : 25\n";
    print "[MAIL] STARTTLS  : required\n";
    print "====================================================\n";

    # --------------------------------------------------------
    # CREATE MESSAGE
    # --------------------------------------------------------

    my $unsigned =
        create_message(
            $to,
            $subject,
            $body
        );

    # --------------------------------------------------------
    # DKIM
    # --------------------------------------------------------

    my $message =
        sign_message(
            $unsigned,
            $private_key
        );

    # --------------------------------------------------------
    # MX LOOKUP
    # --------------------------------------------------------

    my @mx =
        lookup_mx($domain);

    # --------------------------------------------------------
    # NORMAL MX DELIVERY
    # --------------------------------------------------------

    if (@mx) {

        foreach my $record (@mx) {

            my $mx_host =
                $record->{host};

            if (
                try_mx(
                    $mx_host,
                    $to,
                    $message
                )
            ) {

                print "\n====================================================\n";
                print "[SUCCESS] SMTP server accepted the message.\n";
                print "====================================================\n";

                return 1;
            }
        }

        print "\n[FAIL] All MX hosts failed.\n";

        return 0;
    }

    # --------------------------------------------------------
    # NO MX:
    #
    # RFC SMTP fallback is the domain itself.
    # --------------------------------------------------------

    print "\n[DNS] No MX exists.\n";
    print "[DNS] Trying implicit MX: $domain\n";

    my ($ipv6, $ipv4) =
        lookup_addresses($domain);

    foreach my $ip (@$ipv6) {

        print "\n[FALLBACK] IPv6 $ip\n";

        my $ok;

        eval {

            $ok = smtp_session(
                $ip,
                AF_INET6,
                $domain,
                $to,
                $message
            );
        };

        if ($@) {

            print "[FALLBACK] Error: $@\n";

            $ok = 0;
        }

        return 1 if $ok;
    }

    foreach my $ip (@$ipv4) {

        print "\n[FALLBACK] IPv4 $ip\n";

        my $ok;

        eval {

            $ok = smtp_session(
                $ip,
                AF_INET,
                $domain,
                $to,
                $message
            );
        };

        if ($@) {

            print "[FALLBACK] Error: $@\n";

            $ok = 0;
        }

        return 1 if $ok;
    }

    print "\n[FAIL] No usable destination SMTP server found.\n";

    return 0;
}

# ============================================================
# STARTUP
# ============================================================

print <<'BANNER';

============================================================
 Perl Direct SMTP Sender
============================================================

Features:

  * Dynamic recipient MX lookup
  * MX preference ordering
  * AAAA + A lookup
  * IPv6 + IPv4 support
  * Direct SMTP port 25
  * STARTTLS
  * TLS certificate verification
  * Correct SNI hostname
  * EHLO before STARTTLS
  * EHLO after STARTTLS
  * DKIM RSA-SHA256
  * SMTP multiline response handling
  * SMTP dot-stuffing
  * MX fallback
  * Interactive sending loop

============================================================

BANNER

# ------------------------------------------------------------
# Load DKIM key once.
# ------------------------------------------------------------

my $private_key =
    load_dkim_key();

print "\n[READY] SMTP sender is ready.\n";

# ============================================================
# INTERACTIVE LOOP
# ============================================================

while (1) {

    print "\nReceiver email (or 'exit'): ";

    my $to = <STDIN>;

    last unless defined $to;

    chomp($to);

    $to = normalize_email($to);

    last if lc($to) eq "exit";

    unless ($to =~ /\@/) {

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

        send_mail(
            $to,
            $subject,
            $body,
            $private_key
        );
    };

    if ($@) {

        print "\n====================================================\n";
        print "[ERROR]\n";
        print $@;
        print "====================================================\n";
    }
}

print "\n[EXIT] Sender stopped.\n";
