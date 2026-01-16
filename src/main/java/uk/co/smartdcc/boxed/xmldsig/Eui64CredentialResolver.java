/*
 * Created on Mon Jan 16 2026
 *
 * Copyright (c) 2022 Smart DCC Limited
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package uk.co.smartdcc.boxed.xmldsig;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public interface Eui64CredentialResolver {
  /**
   * Lookup certificate for the given identifier.
   *
   * @param eui64
   * @return certificate or null
   */
  X509Certificate lookup(String eui64);

  /**
   * Lookup private key for given identifier.
   *
   * @param eui64
   * @return private key or null
   */
  PrivateKey lookup_key(String eui64);
}
