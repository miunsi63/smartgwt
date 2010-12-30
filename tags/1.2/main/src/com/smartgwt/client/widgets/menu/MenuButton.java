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
 
package com.smartgwt.client.widgets.menu;



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
 * Simple subclass of button associated with a menu widget (gets shown below the button).
 */
public class MenuButton extends Button {

    public static MenuButton getOrCreateRef(JavaScriptObject jsObj) {
        if(jsObj == null) return null;
        BaseWidget obj = BaseWidget.getRef(jsObj);
        if(obj != null) {
            return (MenuButton) obj;
        } else {
            return new MenuButton(jsObj);
        }
    }

    public MenuButton(){
        
    }

    public MenuButton(JavaScriptObject jsObj){
        super(jsObj);
    }

    public MenuButton(String title) {
        setTitle(title);
        
    }

    public MenuButton(String title, Menu menu) {
        setTitle(title);
		setMenu(menu);
        
    }

    protected native JavaScriptObject create()/*-{
        var config = this.@com.smartgwt.client.widgets.BaseWidget::getConfig()();
        var widget = $wnd.isc.MenuButton.create(config);
        this.@com.smartgwt.client.widgets.BaseWidget::doInit()();
        return widget;
    }-*/;
    // ********************* Properties / Attributes ***********************

    /**
     * Default title for the button.
     *
     * @param title title Default value is "Show Menu"
     */
    public void setTitle(String title) {
        setAttribute("title", title, true);
    }

    /**
     * Default title for the button.
     *
     *
     * @return String
     */
    public String getTitle()  {
        return getAttributeAsString("title");
    }

    /**
     * show menu button image (up / down arrowhead) for this menu button
     * Setter for the 'showMenuButtonImage' property - shows/hides the menu button image at runtime
     *
     * @param showMenuButtonImage Should the image be shown. Default value is true
     * @throws IllegalStateException this property cannot be changed after the component has been created
     */
    public void setShowMenuButtonImage(Boolean showMenuButtonImage)  throws IllegalStateException {
        setAttribute("showMenuButtonImage", showMenuButtonImage, false);
    }

    /**
     * show menu button image (up / down arrowhead) for this menu button
     *
     *
     * @return Boolean
     */
    public Boolean getShowMenuButtonImage()  {
        return getAttributeAsBoolean("showMenuButtonImage");
    }

    /**
     * Image for menu button indicating that the button expands a menu.  This image is shown for menus expanding down from the
     * button.   Menu direction is controlled by {@link com.smartgwt.client.widgets.menu.MenuButton#getShowMenuBelow
     * showMenuBelow}.
     * <p><b>Note : </b> This is an advanced setting</p>
     *
     * @param menuButtonImage menuButtonImage Default value is "[SKIN]menu_button.gif"
     * @throws IllegalStateException this property cannot be changed after the component has been created
     */
    public void setMenuButtonImage(String menuButtonImage)  throws IllegalStateException {
        setAttribute("menuButtonImage", menuButtonImage, false);
    }

    /**
     * Image for menu button indicating that the button expands a menu.  This image is shown for menus expanding down from the
     * button.   Menu direction is controlled by {@link com.smartgwt.client.widgets.menu.MenuButton#getShowMenuBelow
     * showMenuBelow}.
     *
     *
     * @return String
     */
    public String getMenuButtonImage()  {
        return getAttributeAsString("menuButtonImage");
    }

    /**
     * Image for menu button indicating that the button expands a menu.  This image is shown for menus expanding up from the
     * button.   Menu direction is controlled by {@link com.smartgwt.client.widgets.menu.MenuButton#getShowMenuBelow
     * showMenuBelow}.
     * <p><b>Note : </b> This is an advanced setting</p>
     *
     * @param menuButtonImageUp menuButtonImageUp Default value is "[SKIN]menu_button_up.gif"
     * @throws IllegalStateException this property cannot be changed after the component has been created
     */
    public void setMenuButtonImageUp(String menuButtonImageUp)  throws IllegalStateException {
        setAttribute("menuButtonImageUp", menuButtonImageUp, false);
    }

    /**
     * Image for menu button indicating that the button expands a menu.  This image is shown for menus expanding up from the
     * button.   Menu direction is controlled by {@link com.smartgwt.client.widgets.menu.MenuButton#getShowMenuBelow
     * showMenuBelow}.
     *
     *
     * @return String
     */
    public String getMenuButtonImageUp()  {
        return getAttributeAsString("menuButtonImageUp");
    }

    /**
     * If this MenuButton has a specified {@link com.smartgwt.client.widgets.Canvas#getAccessKey 'accessKey'}, underline it in
     * the title of the button by default
     *
     * @param hiliteAccessKey hiliteAccessKey Default value is true
     * @throws IllegalStateException this property cannot be changed after the component has been created
     */
    public void setHiliteAccessKey(Boolean hiliteAccessKey)  throws IllegalStateException {
        setAttribute("hiliteAccessKey", hiliteAccessKey, false);
    }

    /**
     * If this MenuButton has a specified {@link com.smartgwt.client.widgets.Canvas#getAccessKey 'accessKey'}, underline it in
     * the title of the button by default
     *
     *
     * @return Boolean
     */
    public Boolean getHiliteAccessKey()  {
        return getAttributeAsBoolean("hiliteAccessKey");
    }

    /**
     * The menu drops down below the menu button.   Set to false if the menu should appear above the menu button.
     * Setter for the 'showMenuButtonBelow' property - determines whether the menu will be shown above or below the menubutton.
     *
     * @param showMenuBelow True if the menu should be shown below the menubutton.. Default value is true
     */
    public void setShowMenuBelow(Boolean showMenuBelow) {
        setAttribute("showMenuBelow", showMenuBelow, true);
    }

    /**
     * The menu drops down below the menu button.   Set to false if the menu should appear above the menu button.
     *
     *
     * @return Boolean
     */
    public Boolean getShowMenuBelow()  {
        return getAttributeAsBoolean("showMenuBelow");
    }
            
    /**
     * The menu to show.
     *
     * @param menu menu Default value is null
     */
    public void setMenu(Menu menu) {
        setAttribute("menu", menu.getOrCreateJsObj(), true);
    }

    /**
     * The menu to show.
     *
     *
     * @return Menu
     */
    public Menu getMenu()  {
            return Menu.getOrCreateRef(getAttributeAsJavaScriptObject("menu"));
    }

    /**
     * Allows you to specify an animation effect to apply to the menu when it is being shown. Valid options are "none" (no
     * animation), "fade", "slide" and "wipe". If unspecified falls through to <code>menu.showAnimationEffect</code>
     * <p><b>Note : </b> This is an advanced setting</p>
     *
     * @param menuAnimationEffect menuAnimationEffect Default value is null
     */
    public void setMenuAnimationEffect(String menuAnimationEffect) {
        setAttribute("menuAnimationEffect", menuAnimationEffect, true);
    }

    /**
     * Allows you to specify an animation effect to apply to the menu when it is being shown. Valid options are "none" (no
     * animation), "fade", "slide" and "wipe". If unspecified falls through to <code>menu.showAnimationEffect</code>
     *
     *
     * @return String
     */
    public String getMenuAnimationEffect()  {
        return getAttributeAsString("menuAnimationEffect");
    }

    // ********************* Methods ***********************



    // ********************* Static Methods ***********************

}




