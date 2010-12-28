/*
 * SmartGWT (GWT for SmartClient)
 * Copyright 2008 and beyond, Isomorphic Software, Inc.
 *
 * SmartGWT is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version 3
 * as published by the Free Software Foundation.  SmartGWT is also
 * available under typical commercial license terms - see
 * http://smartclient.com/license
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 */
 
package com.smartgwt.client.widgets.form;



import com.smartgwt.client.event.*;
import com.smartgwt.client.core.*;
import com.smartgwt.client.types.*;
import com.smartgwt.client.data.*;
import com.smartgwt.client.data.events.*;
import com.smartgwt.client.rpc.*;
import com.smartgwt.client.widgets.*;
import com.smartgwt.client.widgets.events.*;
import com.smartgwt.client.widgets.form.*;
import com.smartgwt.client.widgets.form.validator.*;
import com.smartgwt.client.widgets.form.fields.*;
import com.smartgwt.client.widgets.tile.*;
import com.smartgwt.client.widgets.tile.events.*;
import com.smartgwt.client.widgets.grid.*;
import com.smartgwt.client.widgets.grid.events.*;
import com.smartgwt.client.widgets.layout.*;
import com.smartgwt.client.widgets.menu.*;
import com.smartgwt.client.widgets.tab.*;
import com.smartgwt.client.widgets.toolbar.*;
import com.smartgwt.client.widgets.tree.*;
import com.smartgwt.client.widgets.tree.events.*;
import com.smartgwt.client.widgets.viewer.*;
import com.smartgwt.client.widgets.calendar.*;
import com.smartgwt.client.widgets.calendar.events.*;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

import com.google.gwt.user.client.ui.Widget;
import com.google.gwt.core.client.JavaScriptObject;
import com.google.gwt.user.client.Element;
import com.smartgwt.client.util.JSOHelper;
import com.smartgwt.client.util.EnumUtil;
import com.google.gwt.event.shared.*;
import com.google.gwt.event.shared.HasHandlers;
   /**
    * A SearchForm is a DynamicForm specialized for a user to enter search criteria.&#010 <P>&#010 All DynamicForm properties and methods work on SearchForm.  SearchForm extends and&#010 specializes DynamicForm for searching, for example, SearchForm sets&#010 <code>hiliteRequiredFields</code> false by default because fields are typically required in&#010 a search.

    */
public class SearchForm extends DynamicForm {

    public static SearchForm getOrCreateRef(JavaScriptObject jsObj) {
        if(jsObj == null) return null;
        BaseWidget obj = BaseWidget.getRef(jsObj);
        if(obj != null) {
            return (SearchForm) obj;
        } else {
            return new SearchForm(jsObj);
        }
    }


    public SearchForm(){
        
    }

    public SearchForm(JavaScriptObject jsObj){
        super(jsObj);
    }

    protected native JavaScriptObject create()/*-{
        var config = this.@com.smartgwt.client.widgets.BaseWidget::getConfig()();
        var widget = $wnd.isc.SearchForm.create(config);
        this.@com.smartgwt.client.widgets.BaseWidget::doInit()();
        return widget;
    }-*/;
    // ********************* Properties / Attributes ***********************

    /**
    * If this attribute is true any {@link com.smartgwt.client.data.DataSourceField#getCanFilter canFilter} fields&#010 specified on the dataSource will not be shown unless explicitly included in this component's&#010 {@link com.smartgwt.client.widgets.DataBoundComponent#getFields fields}
    * <p><b>Note : </b> This is an advanced setting</p>
    *
    * @param showFilterFieldsOnly showFilterFieldsOnly Default value is true
    */
    public void setShowFilterFieldsOnly(Boolean showFilterFieldsOnly) {
        setAttribute("showFilterFieldsOnly", showFilterFieldsOnly, true);
    }
    /**
     * If this attribute is true any {@link com.smartgwt.client.data.DataSourceField#getCanFilter canFilter} fields&#010 specified on the dataSource will not be shown unless explicitly included in this component's&#010 {@link com.smartgwt.client.widgets.DataBoundComponent#getFields fields}
     *
     *
     * @return Boolean
     *
     */
    public Boolean getShowFilterFieldsOnly()  {
        return getAttributeAsBoolean("showFilterFieldsOnly");
    }

    // ********************* Methods ***********************


    // ********************* Static Methods ***********************

}


