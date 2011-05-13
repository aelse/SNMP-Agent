package SNMP::Agent;

use warnings;
use strict;

use Carp qw(croak);
use NetSNMP::agent (':all');
use NetSNMP::ASN qw(ASN_OCTET_STR);

sub generic_handler
{

  # $oid, $suboid and $asn_type are provided by the anonymous callback function
  # registered by us, and remaining args come from the NetSNMP::agent module
  my ($root_oid, $suboid_handler, $asn_type, $handler, $registration_info,
    $request_info, $requests)
    = @_;
  my $request;

  for ($request = $requests ; $request ; $request = $request->next())
  {
    my $oid = $request->getOID();
    my $mode = $request->getMode();

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

sub run($)
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
      $suboid_handler = ($asn_type == ASN_OCTET_STR) ?
        sub { return "$suboid_handler" } : sub { return $suboid_handler };
    }

    $agent->register($self->{name}, $oid,
      sub { generic_handler($oid, $suboid_handler, $asn_type, @_) });
  }

  my $running = 1;
  while ($running)
  {
    $agent->agent_check_and_process(1);
  }

  $agent->shutdown();
}

sub new
{
  my $class = shift;
  my ($name, $root_oid, $suboid_handler_map) = @_;

  my $self = {
    name       => 'example_agent',
    root_oid   => '1.3.6.1.4.1.8072.9999.9999.1',
    suboid_map => {},
  };

  croak "Invalid agent name" unless ($name     =~ /^\w+$/);
  croak "Invalid root oid"   unless ($root_oid =~ /^[\d\.]+$/);
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

=pod

=head1 NAME

SNMP::Agent - A simple SNMP AgentX subagent

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';


=head1 SYNOPSIS

Eliminates most of the hassle in developing simple SNMP subagents in perl.
A list of SNMP OIDs are registered to callbacks that return the data.

=head2 Example Code

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

No caching of responses is done by BP::SNMP_Agent.  Any results from
expensive operations should probably be cached for some time in case
of duplicate requests for the same information.


=head1 AUTHOR

Alexander Else, C<< <aelse at else.id.au> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-snmp-agent at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=SNMP-Agent>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

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

1; # End of SNMP::Agent
