package SNMP::Agent;

=pod

=head1 NAME

SNMP::Agent - A simple SNMP AgentX subagent

=head1 VERSION

Version 0.03

=cut

our $VERSION = '0.03';

=head1 SYNOPSIS

Eliminates most of the hassle in developing simple SNMP subagents in perl.
A list of SNMP OIDs are registered to callbacks that return the data.

=cut

use warnings;
use strict;

use Carp qw(croak);
use NetSNMP::agent (':all');
use NetSNMP::ASN qw(ASN_OCTET_STR);

=head1 FUNCTIONS

=cut

sub _generic_handler
{

  # $oid, $suboid_handler and $asn_type are provided by the anonymous callback
  # registered by us, and remaining args come from the NetSNMP::agent module
  my ($root_oid, $suboid_handler, $asn_type, $handler, $registration_info,
    $request_info, $requests)
    = @_;
  my $request;

  for ($request = $requests ; $request ; $request = $request->next())
  {
    my $oid  = $request->getOID();
    my $mode = $request_info->getMode();

    if ($mode == MODE_GET)
    {
      if ($oid == new NetSNMP::OID($root_oid))
      {
        $request->setValue($asn_type, $suboid_handler->($oid, $mode));
      }
    }
    elsif ($mode == MODE_GETNEXT)
    {
      if ($oid < new NetSNMP::OID($root_oid))
      {
        $request->setOID($root_oid);
        $request->setValue($asn_type, $suboid_handler->($oid, $mode));
      }
    }
    elsif ($mode == MODE_SET_RESERVE1)
    {
      if ($oid != new NetSNMP::OID($root_oid))
      {
        $request->setError($request_info, SNMP_ERR_NOSUCHNAME);
      }
    }
    elsif ($mode == MODE_SET_ACTION)
    {
      $suboid_handler->($oid, $mode, $request->getValue());
    }
  }
}

=head2 new

Get an SNMP::Agent object. See EXAMPLES for use.

=cut
sub new
{
  my $class = shift;
  my ($name, $root_oid, $suboid_handler_map) = @_;

  my $self = {
    name       => 'example_agent',
    root_oid   => '1.3.6.1.4.1.8072.9999.9999.1',
    suboid_map => {},
  };

  croak "Invalid agent name" unless ($name =~ /^\w+$/);
  croak "Need hash reference to suboid handlers"
    unless (ref $suboid_handler_map eq "HASH");

  foreach my $suboid (keys %$suboid_handler_map)
  {
    my $handler  = $suboid_handler_map->{$suboid}->{handler};
    my $asn_type = $suboid_handler_map->{$suboid}->{type};
    $asn_type ||= ASN_OCTET_STR;

    my $ref_type = ref $handler;
    croak "Invalid suboid: $suboid" unless ($suboid =~ /^[\d\.]*/);
    croak "Not function reference or scalar for suboid $suboid"
      unless ($ref_type eq 'CODE' || $ref_type eq 'SCALAR');

    $suboid =~ s/^\.//;
    $self->{suboid_map}->{$suboid} = {handler => $handler, type => $asn_type};
  }

  $self->{name} = $name;
  $root_oid =~ s/\.$//;
  $self->{root_oid} = $root_oid;

  bless $self, $class;
  return $self;
}

=head2 run

Called on an SNMP::Agent object with no arguments to start the agent.

=cut
sub run
{
  my $self = shift;

  my $agent = new NetSNMP::agent(

    # makes the agent read a my_agent_name.conf file
    'Name'   => $self->{name},
    'AgentX' => 1
  );

  # register each oid handler individually to the same callback function
  my $root_oid = $self->{root_oid};
  foreach my $suboid (keys %{$self->{suboid_map}})
  {
    my $oid            = join('.', ($root_oid, $suboid));
    my $suboid_handler = $self->{suboid_map}->{$suboid}->{handler};
    my $asn_type       = $self->{suboid_map}->{$suboid}->{type};

    # All suboid handlers are a sub ref.
    if (ref $suboid_handler ne 'CODE')
    {
      $suboid_handler =
        ($asn_type == ASN_OCTET_STR)
        ? sub { return "$suboid_handler" }
        : sub { return $suboid_handler };
    }

    $agent->register($self->{name}, $oid,
      sub { _generic_handler($oid, $suboid_handler, $asn_type, @_) });
  }

  my $running = 1;
  while ($running)
  {
    $agent->agent_check_and_process(1);
  }

  $agent->shutdown();
}


=head1 EXAMPLES

  use SNMP::Agent;
  use NetSNMP::ASN qw/ASN_GAUGE/;

  sub do_one { return int(rand(10)) }
  sub do_two { return "two" }

  my $root_oid = '1.3.6.1.4.1.8072.9999.9999.123';
  my %handlers = (
    '1' => { handler => \&do_one, type => ASN_GAUGE },
    '2' => { handler => \&do_two },     # default type ASN_OCTET_STR
  );

  my $agent = new SNMP::Agent('my_agent', $root_oid, \%handlers);
  $agent->run();

=head2 Output

With the agent running,

  # snmpwalk -v 2c -c public localhost 1.3.6.1.4.1.8072.9999.9999.123
  iso.3.6.1.4.1.8072.9999.9999.123.1 = Gauge32: 2
  iso.3.6.1.4.1.8072.9999.9999.123.2 = STRING: "two"

=head1 NOTES

=head2 Callbacks

The callback functions specified to handle OID requests are called
for SNMP sets as well as get requests. The requested OID and the
request type are passed as arguments to the callback. If the mode
is MODE_SET_ACTION there is a third argument, the value to be set.

  use NetSNMP::agent qw(MODE_SET_ACTION);
  my $persistent_val = 0;

  sub do_one
  {
    my ($oid, $mode, $value) = @_;
    if ($mode == MODE_SET_ACTION)
    {
      $persistent_val = $value;
    }
    else
    {
      return $persistent_val;
    }
  }

=head2 Caching

No caching of responses is done by SNMP::Agent.  Any results from
expensive operations should probably be cached for some time in case
of duplicate requests for the same information.

=head1 AUTHOR

Alexander Else, C<< <aelse at else.id.au> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-snmp-agent at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=SNMP-Agent>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

=head2 COUNTER64

Strange values are returned for non-zero 64 bit counters. I suspect something in either NetSNMP::agent or communication
between it and the snmp daemon. From cursory investigation it does not appear to be a simple endian problem. I may be wrong.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc SNMP::Agent


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=SNMP-Agent>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/SNMP-Agent>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/SNMP-Agent>

=item * Search CPAN

L<http://search.cpan.org/dist/SNMP-Agent/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2011 Alexander Else.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1;    # End of SNMP::Agent
