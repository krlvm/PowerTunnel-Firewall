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

package io.github.krlvm.powertunnel.plugins.firewall.listeners;

import io.github.krlvm.powertunnel.plugins.firewall.FirewallPlugin;
import io.github.krlvm.powertunnel.sdk.http.ProxyRequest;
import io.github.krlvm.powertunnel.sdk.http.ProxyResponse;
import io.github.krlvm.powertunnel.sdk.proxy.ProxyAdapter;
import org.jetbrains.annotations.NotNull;

public class RequestListener extends ProxyAdapter {

    private final FirewallPlugin firewall;
    private final ProxyResponse response;

    public RequestListener(FirewallPlugin firewall, String accessDeniedHtml) {
        this.firewall = firewall;
        this.response = firewall.getServer().getProxyServer().getResponseBuilder(accessDeniedHtml, 403).build();
    }

    @Override
    public void onClientToProxyRequest(@NotNull ProxyRequest request) {
        if(request.isBlocked()) return;
        if(firewall.isBlocked(request.getHost())) {
            request.setResponse(response);
        }
    }
}
