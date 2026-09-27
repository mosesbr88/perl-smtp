#!/usr/bin/perl

use strict;
use warnings;
use IO::Socket::INET;
use File::Path qw(make_path);

my $HOST = "0.0.0.0";
my $PORT = 25;
my $MAIL_DIR = "received_emails";

make_path($MAIL_DIR) unless -d $MAIL_DIR;

my $server = IO::Socket::INET->new(
    LocalAddr => $HOST,
    LocalPort => $PORT,
    Proto     => "tcp",
    Listen    => 20,
    ReuseAddr => 1
) or die "Cannot listen on port $PORT: $!\n";

print "========================================\n";
print " SMTP SERVER STARTED\n";
print " Listening: $HOST:$PORT\n";
print " Mail directory: $MAIL_DIR/\n";
print "========================================\n";

while (my $client = $server->accept()) {

    $client->autoflush(1);

    my $peer = $client->peerhost();

    print "\n[+] Connection from $peer\n";

    print $client "220 no-vnc-production.up.railway.app ESMTP Ready\r\n";

    my $mail_from = "";
    my @recipients;

    while (my $line = <$client>) {

        $line =~ s/\r?\n$//;

        print "[SMTP] $line\n";

        # EHLO / HELO
        if ($line =~ /^EHLO\s+/i || $line =~ /^HELO\s+/i) {

            print $client "250-no-vnc-production.up.railway.app\r\n";
            print $client "250-8BITMIME\r\n";
            print $client "250 SIZE 10485760\r\n";

        }

        # MAIL FROM
        elsif ($line =~ /^MAIL FROM:\s*(.*)/i) {

            $mail_from = $1;
            @recipients = ();

            print $client "250 2.1.0 OK\r\n";

        }

        # RCPT TO
        elsif ($line =~ /^RCPT TO:\s*(.*)/i) {

            push @recipients, $1;

            print $client "250 2.1.5 OK\r\n";

        }

        # DATA
        elsif ($line =~ /^DATA$/i) {

            if (!$mail_from || !@recipients) {

                print $client
                    "503 5.5.1 Need MAIL FROM and RCPT TO first\r\n";

                next;
            }

            print $client
                "354 End data with <CR><LF>.<CR><LF>\r\n";

            my $data = "";

            while (my $data_line = <$client>) {

                last if $data_line eq ".\r\n";
                last if $data_line eq ".\n";

                # SMTP dot-stuffing
                $data_line =~ s/^\.\./\./;

                $data .= $data_line;
            }

            my ($sec, $min, $hour, $mday, $mon, $year) = localtime();

            $year += 1900;
            $mon++;

            my $filename = sprintf(
                "%s/%04d%02d%02d_%02d%02d%02d_%d.eml",
                $MAIL_DIR,
                $year,
                $mon,
                $mday,
                $hour,
                $min,
                $sec,
                $$ 
            );

            if (open(my $fh, ">", $filename)) {

                print $fh $data;
                close($fh);

                print "\n========================================\n";
                print "[+] EMAIL RECEIVED\n";
                print "FROM: $mail_from\n";
                print "TO: " . join(", ", @recipients) . "\n";
                print "FILE: $filename\n";
                print "========================================\n";

                print $client "250 2.0.0 Message accepted\r\n";

            } else {

                print "[!] Failed to save email: $!\n";

                print $client
                    "451 4.3.0 Cannot save message\r\n";
            }

            $mail_from = "";
            @recipients = ();
        }

        # RSET
        elsif ($line =~ /^RSET$/i) {

            $mail_from = "";
            @recipients = ();

            print $client "250 2.0.0 Reset OK\r\n";
        }

        # NOOP
        elsif ($line =~ /^NOOP$/i) {

            print $client "250 2.0.0 OK\r\n";
        }

        # QUIT
        elsif ($line =~ /^QUIT$/i) {

            print $client "221 2.0.0 Bye\r\n";

            last;
        }

        # Unknown command
        else {

            print $client "502 5.5.2 Command not recognized\r\n";
        }
    }

    close($client);

    print "[-] Connection closed: $peer\n";
}
