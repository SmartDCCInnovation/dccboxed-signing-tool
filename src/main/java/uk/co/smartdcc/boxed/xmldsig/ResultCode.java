/*
 * Created on Fri Aug 26 2022
 *
 * Copyright (c) 2022 Smart DCC Limited
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package uk.co.smartdcc.boxed.xmldsig;

public enum ResultCode {
  SUCCESS(0), OS_FAIL(1), GENERIC_ERROR(2), MISSING_KEY(3), VALIDATION_FAIL(10);

  private final int _v;

  ResultCode(final int v) {
    this._v = v;
  }

  public int value() {
    return _v;
  }
}
