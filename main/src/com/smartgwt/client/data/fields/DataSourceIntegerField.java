/*
 * SmartGWT (GWT for SmartClient)
 * Copyright 2008 and beyond, Isomorphic Software, Inc.
 *
 * SmartGWT is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version 3
 * as published by the Free Software Foundation.  SmartGWT is also
 * available under typical commercial license terms - see
 * smartclient.com/license.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 */

package com.smartgwt.client.data.fields;

import com.smartgwt.client.data.DataSourceField;
import com.smartgwt.client.types.FieldType;


public class DataSourceIntegerField extends DataSourceField {

    public DataSourceIntegerField() {
        setType(FieldType.INTEGER);
    }

    public DataSourceIntegerField(String name) {
        super(name, FieldType.INTEGER);
    }

    public DataSourceIntegerField(String name, String title) {
        super(name, FieldType.INTEGER, title);
    }

    public DataSourceIntegerField(String name, String title, int length) {
        super(name, FieldType.INTEGER, title, length);
    }

    public DataSourceIntegerField(String name, String title, int length, boolean required) {
        super(name, FieldType.INTEGER, title, length, required);
    }
}
