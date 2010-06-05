=head1 NAME

AnyEvent::FCP - freenet client protocol 2.0

=head1 SYNOPSIS

   use AnyEvent::FCP;

   my $fcp = new AnyEvent::FCP;

   # transactions return condvars
   my $lp_cv = $fcp->list_peers;
   my $pr_cv = $fcp->list_persistent_requests;

   my $peers = $lp_cv->recv;
   my $reqs  = $pr_cv->recv;

=head1 DESCRIPTION

This module implements the freenet client protocol version 2.0, as used by
freenet 0.7. See L<Net::FCP> for the earlier freenet 0.5 version.

See L<http://wiki.freenetproject.org/FreenetFCPSpec2Point0> for a
description of what the messages do.

The module uses L<AnyEvent> to find a suitable event module.

Only very little is implemented, ask if you need more, and look at the
example program later in this section.

=head2 EXAMPLE

This example fetches the download list and sets the priority of all files
with "a" in their name to "emergency":

   use AnyEvent::FCP;

   my $fcp = new AnyEvent::FCP;

   $fcp->watch_global_sync (1, 0);
   my $req = $fcp->list_persistent_requests_sync;

   for my $req (values %$req) {
      if ($req->{filename} =~ /a/) {
         $fcp->modify_persistent_request_sync (1, $req->{identifier}, undef, 0);
      }
   }

=head2 IMPORT TAGS

Nothing much can be "imported" from this module right now.

=head2 THE AnyEvent::FCP CLASS

=over 4

=cut

package AnyEvent::FCP;

use common::sense;

use Carp;

our $VERSION = '0.3';

use Scalar::Util ();

use AnyEvent;
use AnyEvent::Handle;

sub touc($) {
   local $_ = shift;
   1 while s/((?:^|_)(?:svk|chk|uri|fcp|ds|mime)(?:_|$))/\U$1/;
   s/(?:^|_)(.)/\U$1/g;
   $_
}

sub tolc($) {
   local $_ = shift;
   1 while s/(SVK|CHK|URI|FCP|DS|MIME)([^_])/$1\_$2/i;
   1 while s/([^_])(SVK|CHK|URI|FCP|DS|MIME)/$1\_$2/i;
   s/(?<=[a-z])(?=[A-Z])/_/g;
   lc
}

=item $fcp = new AnyEvent::FCP [host => $host][, port => $port][, progress => \&cb][, name => $name]

Create a new FCP connection to the given host and port (default
127.0.0.1:9481, or the environment variables C<FREDHOST> and C<FREDPORT>).

If no C<name> was specified, then AnyEvent::FCP will generate a
(hopefully) unique client name for you.

You can install a progress callback that is being called with the AnyEvent::FCP
object, the type, a hashref with key-value pairs and a reference to any received data,
for all unsolicited messages.

Example:

   sub progress_cb {
      my ($self, $type, $kv, $rdata) = @_;

      if ($type eq "simple_progress") {
         warn "$kv->{identifier} $kv->{succeeded}/$kv->{required}\n";
      }
   }

=cut

sub new {
   my $class = shift;
   my $self = bless { @_ }, $class;

   $self->{host}     ||= $ENV{FREDHOST} || "127.0.0.1";
   $self->{port}     ||= $ENV{FREDPORT} || 9481;
   $self->{name}     ||= time.rand.rand.rand; # lame
   $self->{timeout}  ||= 600;
   $self->{progress} ||= sub { };

   $self->{id} = "a0";

   {
      Scalar::Util::weaken (my $self = $self);

      $self->{hdl} = new AnyEvent::Handle
         connect  => [$self->{host} => $self->{port}],
         timeout  => $self->{timeout},
         on_error => sub {
            warn "<@_>\n";
            exit 1;
         },
         on_read  => sub { $self->on_read (@_) },
         on_eof   => $self->{on_eof} || sub { };

      Scalar::Util::weaken ($self->{hdl}{fcp} = $self);
   }

   $self->send_msg (
      client_hello =>
      name => $self->{name},
      expected_version => "2.0",
   );

   $self
}

sub send_msg {
   my ($self, $type, %kv) = @_;

   my $data  = delete $kv{data};

   if (exists $kv{id_cb}) {
      my $id = $kv{identifier} || ++$self->{id};
      $self->{id}{$id} = delete $kv{id_cb};
      $kv{identifier} = $id;
   }

   my $msg = (touc $type) . "\012"
             . join "", map +(touc $_) . "=$kv{$_}\012", keys %kv;

      sub id {
         my ($self) = @_;


      }

   if (defined $data) {
      $msg .= "DataLength=" . (length $data) . "\012"
            . "Data\012$data";
   } else {
      $msg .= "EndMessage\012";
   }

   $self->{hdl}->push_write ($msg);
}

sub on_read {
   my ($self) = @_;

   my $type;
   my %kv;
   my $rdata;

   my $done_cb = sub {
      $kv{pkt_type} = $type;

      if (my $cb = $self->{queue}[0]) {
         $cb->($self, $type, \%kv, $rdata)
            and shift @{ $self->{queue} };
      } else {
         $self->default_recv ($type, \%kv, $rdata);
      }
   };

   my $hdr_cb; $hdr_cb = sub {
      if ($_[1] =~ /^([^=]+)=(.*)$/) {
         my ($k, $v) = ($1, $2);
         my @k = split /\./, tolc $k;
         my $ro = \\%kv;

         while (@k) {
            my $k = shift @k;
            if ($k =~ /^\d+$/) {
               $ro = \$$ro->[$k];
            } else {
               $ro = \$$ro->{$k};
            }
         }

         $$ro = $v;

         $_[0]->push_read (line => $hdr_cb);
      } elsif ($_[1] eq "Data") {
         $_[0]->push_read (chunk => delete $kv{data_length}, sub {
            $rdata = \$_[1];
            $done_cb->();
         });
      } elsif ($_[1] eq "EndMessage") {
         $done_cb->();
      } else {
         die "protocol error, expected message end, got $_[1]\n";#d#
      }
   };

   $self->{hdl}->push_read (line => sub {
      $type = tolc $_[1];
      $_[0]->push_read (line => $hdr_cb);
   });
}

sub default_recv {
   my ($self, $type, $kv, $rdata) = @_;

   if ($type eq "node_hello") {
      $self->{node_hello} = $kv;
   } elsif (exists $self->{id}{$kv->{identifier}}) {
      $self->{id}{$kv->{identifier}}($self, $type, $kv, $rdata)
         and delete $self->{id}{$kv->{identifier}};
   } else {
      &{ $self->{progress} };
   }
}

sub _txn {
   my ($name, $sub) = @_;

   *{$name} = sub {
      splice @_, 1, 0, (my $cv = AnyEvent->condvar);
      &$sub;
      $cv
   };

   *{"$name\_sync"} = sub {
      splice @_, 1, 0, (my $cv = AnyEvent->condvar);
      &$sub;
      $cv->recv
   };
}

=item $cv = $fcp->list_peers ([$with_metdata[, $with_volatile]])

=item $peers = $fcp->list_peers_sync ([$with_metdata[, $with_volatile]])

=cut

_txn list_peers => sub {
   my ($self, $cv, $with_metadata, $with_volatile) = @_;

   my @res;

   $self->send_msg (list_peers =>
      with_metadata => $with_metadata ? "true" : "false",
      with_volatile => $with_volatile ? "true" : "false",
      id_cb         => sub {
         my ($self, $type, $kv, $rdata) = @_;

         if ($type eq "end_list_peers") {
            $cv->(\@res);
            1
         } else {
            push @res, $kv;
            0
         }
      },
   );
};

=item $cv = $fcp->list_peer_notes ($node_identifier)

=item $notes = $fcp->list_peer_notes_sync ($node_identifier)

=cut

_txn list_peer_notes => sub {
   my ($self, $cv, $node_identifier) = @_;

   $self->send_msg (list_peer_notes =>
      node_identifier => $node_identifier,
      id_cb           => sub {
         my ($self, $type, $kv, $rdata) = @_;

         $cv->($kv);
         1
      },
   );
};

=item $cv = $fcp->watch_global ($enabled[, $verbosity_mask])

=item $fcp->watch_global_sync ($enabled[, $verbosity_mask])

=cut

_txn watch_global => sub {
   my ($self, $cv, $enabled, $verbosity_mask) = @_;

   $self->send_msg (watch_global =>
      enabled        => $enabled ? "true" : "false",
      defined $verbosity_mask ? (verbosity_mask => $verbosity_mask+0) : (),
   );

   $cv->();
};

=item $cv = $fcp->list_persistent_requests

=item $reqs = $fcp->list_persistent_requests_sync

=cut

_txn list_persistent_requests => sub {
   my ($self, $cv) = @_;

   my %res;

   $self->send_msg ("list_persistent_requests");

   push @{ $self->{queue} }, sub {
      my ($self, $type, $kv, $rdata) = @_;

      if ($type eq "end_list_persistent_requests") {
         $cv->(\%res);
         1
      } else {
         my $id = $kv->{identifier};

         if ($type =~ /^persistent_(get|put|put_dir)$/) {
            $res{$id} = {
               type => $1,
               %{ $res{$id} },
               %$kv,
            };
         } elsif ($type eq "simple_progress") {
            delete $kv->{pkt_type}; # save memory
            push @{ $res{delete $kv->{identifier}}{simple_progress} }, $kv;
         } else {
            $res{delete $kv->{identifier}}{delete $kv->{pkt_type}} = $kv;
         }
         0
      }
   };
};

=item $cv = $fcp->remove_request ($global, $identifier)

=item $status = $fcp->remove_request_sync ($global, $identifier)

=cut

_txn remove_request => sub {
   my ($self, $cv, $global, $identifier) = @_;

   $self->send_msg (remove_request =>
      global     => $global ? "true" : "false",
      identifier => $identifier,
      id_cb      => sub {
         my ($self, $type, $kv, $rdata) = @_;

         $cv->($kv);
         1
      },
   );
};

=item $cv = $fcp->modify_persistent_request ($global, $identifier[, $client_token[, $priority_class]])

=item $sync = $fcp->modify_persistent_request_sync ($global, $identifier[, $client_token[, $priority_class]])

=cut

_txn modify_persistent_request => sub {
   my ($self, $cv, $global, $identifier, $client_token, $priority_class) = @_;

   $self->send_msg (modify_persistent_request =>
      global     => $global ? "true" : "false",
      defined $client_token   ? (client_token   => $client_token  ) : (),
      defined $priority_class ? (priority_class => $priority_class) : (),
      identifier => $identifier,
      id_cb      => sub {
         my ($self, $type, $kv, $rdata) = @_;

         $cv->($kv);
         1
      },
   );
};

=item $cv = $fcp->get_plugin_info ($name, $detailed)

=item $info = $fcp->get_plugin_info_sync ($name, $detailed)

=cut

_txn get_plugin_info => sub {
   my ($self, $cv, $name, $detailed) = @_;

   $self->send_msg (get_plugin_info =>
      plugin_name => $name,
      detailed    => $detailed ? "true" : "false",
      id_cb       => sub {
         my ($self, $type, $kv, $rdata) = @_;

         $cv->($kv);
         1
      },
   );
};

=item $cv = $fcp->client_get ($uri, $identifier, %kv)

=item $status = $fcp->client_get_sync ($uri, $identifier, %kv)

%kv can contain (L<http://wiki.freenetproject.org/FCP2p0ClientGet>).

ignore_ds, ds_only, verbosity, max_size, max_temp_size, max_retries,
priority_class, persistence, client_token, global, return_type,
binary_blob, allowed_mime_types, filename, temp_filename

=cut

_txn client_get => sub {
   my ($self, $cv, $uri, $identifier, %kv) = @_;

   $self->send_msg (client_get =>
      %kv,
      uri        => $uri,
      identifier => $identifier,
      id_cb       => sub {
         my ($self, $type, $kv, $rdata) = @_;

         $cv->($kv);
         1
      },
   );
};

=back

=head1 EXAMPLE PROGRAM

   use AnyEvent::FCP;

   my $fcp = new AnyEvent::FCP;

   # let us look at the global request list
   $fcp->watch_global (1, 0);

   # list them, synchronously
   my $req = $fcp->list_persistent_requests_sync;

   # go through all requests
   for my $req (values %$req) {
      # skip jobs not directly-to-disk
      next unless $req->{return_type} eq "disk";
      # skip jobs not issued by FProxy
      next unless $req->{identifier} =~ /^FProxy:/;

      if ($req->{data_found}) {
         # file has been successfully downloaded
         
         ... move the file away
         (left as exercise)

         # remove the request

         $fcp->remove_request (1, $req->{identifier});
      } elsif ($req->{get_failed}) {
         # request has failed
         if ($req->{get_failed}{code} == 11) {
            # too many path components, should restart
         } else {
            # other failure
         }
      } else {
         # modify priorities randomly, to improve download rates
         $fcp->modify_persistent_request (1, $req->{identifier}, undef, int 6 - 5 * (rand) ** 1.7)
            if 0.1 > rand;
      }
   }

   # see if the dummy plugin is loaded, to ensure all previous requests have finished.
   $fcp->get_plugin_info_sync ("dummy");

=head1 SEE ALSO

L<http://wiki.freenetproject.org/FreenetFCPSpec2Point0>, L<Net::FCP>.

=head1 BUGS

=head1 AUTHOR

 Marc Lehmann <schmorp@schmorp.de>
 http://home.schmorp.de/

=cut

1

