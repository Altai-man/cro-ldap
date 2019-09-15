use Test;
use lib $*PROGRAM.parent.add("lib");
use Test::MockServer;
use Cro::LDAP::Client;
use Cro::LDAP::Control;
use Cro::LDAP::Entry;
use Cro::LDAP::Reference;
use Cro::LDAP::Schema;
use Cro::LDAP::Server;
use Cro::LDAP::Types;
use Test;

my Cro::Service $server = Cro::LDAP::Server.new(
        worker => MockLDAPWorker.new,
        :host('localhost'),
        :20008port);
$server.start;
END $server.stop;

my $client = Cro::LDAP::Client.new;

await $client.connect(:host<localhost>, :port(20008));

my $control = Cro::LDAP::Control::Paged.new(:500size);

{
    my $dn = "test=paged";
    my $filter = "cn=root";
    loop {
        # make a search request
        my $search = $client.search(:$dn, :$filter, :$control);
        react {
            # process all values from the search supply
            whenever $search {
                when Cro::LDAP::Entry { #`( process an entry ) }
                when Cro::LDAP::Search::Done {
                    # when this batch is done, find a control of type...
                    my $paged = .controls.first(Cro::LDAP::Control::Paged);
                    # without a control, end the processing
                    last without $paged;
                    # re-use the response cookie for a new request, if any
                    $control.cookie = $paged.cookie;
                }
                QUIT {
                    # an error has happened, we don't want to search for more
                    $client.search(:$dn, :$filter, control => Cro::LDAP::Control::Paged.new(:0size, :cookie($control.cookie)));
                    # process the error
                }
            }
        }
        last unless $control.cookie.elems;
    }
}

done-testing;
