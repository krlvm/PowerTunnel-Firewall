/*
 * This file is part of PowerTunnel-Firewall.
 *
 * PowerTunnel-Firewall is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * PowerTunnel-Firewall is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with PowerTunnel-Firewall.  If not, see <https://www.gnu.org/licenses/>.
 */

package io.github.krlvm.powertunnel.plugins.firewall;

import io.github.krlvm.powertunnel.plugins.firewall.enums.FiltrationMode;
import io.github.krlvm.powertunnel.plugins.firewall.enums.FirewallMode;
import io.github.krlvm.powertunnel.plugins.firewall.listeners.DNSListener;
import io.github.krlvm.powertunnel.plugins.firewall.listeners.RequestListener;
import io.github.krlvm.powertunnel.sdk.plugin.PowerTunnelPlugin;
import io.github.krlvm.powertunnel.sdk.proxy.ProxyServer;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

public class FirewallPlugin extends PowerTunnelPlugin {

    private static final Logger LOGGER = LoggerFactory.getLogger(FirewallPlugin.class);

    private FirewallMode firewallMode;
    private String[] list;
    private String[] exclusionList;

    @Override
    public void onProxyInitialization(@NotNull ProxyServer proxy) {
        String[] hosts;
        try {
            final String s = readTextFile("firewall-hosts.txt");
            hosts = s.isEmpty() ? new String[0] : s.split("\n");
        } catch (IOException ex) {
            LOGGER.error("Failed to read filtration list: {}", ex.getMessage(), ex);
            return;
        }
        if(hosts.length == 0) {
            LOGGER.warn("Filtration list is empty");
        }

        String accessDeniedHtml;
        try {
            accessDeniedHtml = readTextFile("firewall-access-denied.html");
        } catch (IOException ex) {
            LOGGER.error("Failed to read \"access denied\" response: {}", ex.getMessage(), ex);
            accessDeniedHtml = "";
        }

        final Set<String> listSet = new HashSet<>();
        final Set<String> exclusionListSet = new HashSet<>();
        for(String host : hosts) {
            if (host.startsWith("-")) {
                exclusionListSet.add(host.replaceFirst("-", ""));
            } else {
                listSet.add(host);
            }
        }
        list = listSet.toArray(new String[0]);
        exclusionList = exclusionListSet.isEmpty() ? null : exclusionListSet.toArray(new String[0]);

        this.firewallMode = FirewallMode.valueOf(readConfiguration().get("firewall_mode", FirewallMode.BLACKLIST.toString()).toUpperCase());
        final FiltrationMode mode = FiltrationMode.valueOf(readConfiguration().get("filtration_mode", FiltrationMode.DNS.toString()).toUpperCase());

        final boolean filterDns = mode == FiltrationMode.DNS || mode == FiltrationMode.BOTH;
        final boolean filterProxy = mode == FiltrationMode.PROXY || mode == FiltrationMode.BOTH;

        if(filterDns) {
            registerProxyListener(new DNSListener(this), -5);
        }
        if(filterProxy) {
            registerProxyListener(new RequestListener(this, accessDeniedHtml), -5);
        }

        LOGGER.info("Filtration enabled for {} hosts ({} hosts are excluded) in {} mode with {} filtration type",
                list.length, exclusionList == null ? 0 : exclusionList.length, firewallMode, mode);
    }

    public FirewallMode getFirewallMode() {
        return firewallMode;
    }
    public boolean isBlocked(final String host) {
        return (firewallMode == FirewallMode.BLACKLIST) ?
                (isListed(host) && !isExcluded(host)) :
                (!isListed(host) || isExcluded(host));
    }

    public boolean isListed(final String host) {
        if(list == null || host == null) return false;
        for (String s : list) {
            if(host.endsWith(s)) return true;
        }
        return false;
    }
    public boolean isExcluded(final String host) {
        if(exclusionList == null || host == null) return false;
        for (String s : exclusionList) {
            if(host.endsWith(s)) return true;
        }
        return false;
    }
}
