/*
 * Smart GWT (GWT for SmartClient)
 * Copyright 2008 and beyond, Isomorphic Software, Inc.
 *
 * Smart GWT is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version 3
 * is published by the Free Software Foundation.  Smart GWT is also
 * available under typical commercial license terms - see
 * http://smartclient.com/license
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 */

package com.smartgwt.client;

import com.google.gwt.core.client.EntryPoint;
import com.google.gwt.core.client.GWT;
import com.google.gwt.user.client.Window;
import com.smartgwt.client.rpc.RPCManager;
import com.smartgwt.client.types.PromptStyle;
import com.smartgwt.client.util.I18nUtil;
import com.smartgwt.client.util.LogUtil;

/**
 * Internal Smart GWT Entry point class where framework level initialization code executes
 * before the users EntryPoint is run.
 */
public class SmartGwtEntryPoint implements EntryPoint {
    private static boolean initialized = false;

    private static native void init() /*-{
        //pre GWT 2.0 fallback
        if(typeof $entry === "undefined") {
            $entry = function(jsFunction) {
                        return jsFunction;
                     };
        }
        if ($wnd.isc.Browser.isIE && $wnd.isc.Browser.version >= 7) {
            $wnd.isc.EventHandler._IECanSetKeyCode = {};
        }
        //debox Java primitive values for Javascript in hosted mode.
        $debox = function(val) {
            return @com.google.gwt.core.client.GWT::isScript()() ? val : function() {
            var v = val.apply(this, arguments);
            return v == undefined || v == null ? null : v.valueOf();
        }};

        if(!@com.google.gwt.core.client.GWT::isScript()()){
            $wnd.isc.Log.addClassMethods({
              warningLogged : function (message) {
                  @com.google.gwt.core.client.GWT::log(Ljava/lang/String;Ljava/lang/Throwable;)(message, @com.smartgwt.client.core.JsObject.SGWT_WARN::new(Ljava/lang/String;)(message));
              }
            });
            //support option of triggering JS debugger by default in hosted mode if JS error is encountered
            @com.smartgwt.client.util.SC::setEnableJSDebugger(Z)(true);

            //allow lazy loading of grids to work in hosted mode
            $wnd.Array.LOADING = new Object();

            $wnd.isc.isA.FUNCTION_STR = '[object Function]';
            $wnd.isc.isA.DATE_STR = '[object Date]';
            $wnd.isc.isA.ARRAY_STR = '[object Array]';

            $wnd.isc.isA.Function = function (object) {
                if (object == null) return false;
                return Object.prototype.toString.apply(object) === this.FUNCTION_STR;
            };
            $wnd.isc.isA.String = function (object) {
                if (object == null) return false;
                if (object.Class != null && object.Class == this._$String) return true;
                return typeof object == "string";
            };
            $wnd.isc.isA.Number = function (object) {
                if (object == null) return false;
                return typeof object === 'number' && isFinite(object);
            };
            $wnd.isc.isA.Boolean = function (object) {
                if (object == null) return false;
                return typeof object == "boolean";
            };
            $wnd.isc.isA.Date = function (object) {
                if (object == null) return false;
                return Object.prototype.toString.apply(object) === this.DATE_STR;
            };
            $wnd.isc.isA.Array = function (object) {
                if (object == null) return false;
                return Object.prototype.toString.apply(object) === this.ARRAY_STR;
            };
        }

		// Set a flag so SC code can easily determine that SGWT is running
		$wnd.isc.Browser.isSGWT = true;

        //convert javascript data types into corresponding Java wrapper types
        //int -> Integer, float -> Float, boolean -> Boolean and date - > java.util.Date
        $wnd.SmartGWT ={};
        $wnd.SmartGWT.convertToJavaType = function(obj) {
                if(obj == null || obj === undefined) return null;
                var objType = typeof obj;
                if(objType == 'string') {
                    return obj;
                } else if (objType == 'number') {
                    if(obj.toString().indexOf('.') == -1) {
                        if(obj <= @java.lang.Integer::MAX_VALUE) {
                            return @com.smartgwt.client.util.JSOHelper::toInteger(I)(obj);
                        } else {
                          return @com.smartgwt.client.util.JSOHelper::toLong(D)(obj);
                        }
                    } else {
                        if(obj <= @java.lang.Float::MAX_VALUE) {
                            return @com.smartgwt.client.util.JSOHelper::toFloat(F)(obj);
                        } else {
                            return @com.smartgwt.client.util.JSOHelper::toDouble(D)(obj);
                        }
                    }
                } else if(objType == 'boolean') {
                    return @com.smartgwt.client.util.JSOHelper::toBoolean(Z)(obj);
                } else if($wnd.isA.Date(obj)) {
                    return @com.smartgwt.client.util.JSOHelper::toDate(D)(obj.getTime());
                } else if (obj._constructor && obj._constructor == 'DateRange') {
                    return @com.smartgwt.client.widgets.form.fields.DateRangeItem::convertToDateRange(Lcom/google/gwt/core/client/JavaScriptObject;)(obj);
                } else if(@com.smartgwt.client.util.JSOHelper::isJSO(Ljava/lang/Object;)(obj)) {
                    return obj;
                } else if($wnd.isA.Array(obj)) {
                    return @com.smartgwt.client.util.JSOHelper::convertToJavaObjectArray(Lcom/google/gwt/core/client/JavaScriptObject;)(obj);
                } else {
                    //handle case where object may be a GWT created class instance
                    return obj;
                }
        };

        $wnd.SmartGWT.convertToJavaObject = function (object, listAsArray) {
    		if (object == null) return null;

	    	if (!$wnd.isc.isA.Object(object)) {

	    		return $wnd.SmartGWT.convertToJavaType(object);
	    	} else if ($wnd.isc.isA.Date(object)) {

	    		return @com.smartgwt.client.util.JSOHelper::toDate(D)(object.getTime());
	    	} else if ($wnd.isc.isAn.Array(object)) {

	    		var convertedArray = [];
	    		for (var i = 0; i < object.length; i++) {
	    			convertedArray[i] =  $wnd.SmartGWT.convertToJavaObject(object[i]);
	    		}
	    		// now we've converted all our members and we need to return a Java array or List
	    		if (listAsArray) {
	    			return  @com.smartgwt.client.util.JSOHelper::convertToJavaObjectArray(Lcom/google/gwt/core/client/JavaScriptObject;)(convertedArray);
	    		} else {

	    			var javaList = @java.util.ArrayList::new()();
	    			for (var i = 0; i < convertedArray.length; i++) {
	    				javaList.@java.util.ArrayList::add(Ljava/lang/Object;)(convertedArray[i]);
	    			}
	    			return javaList;
	    		}
	    	 } else {
	    	 	// convert to a map
	    	 	var javaMap = @java.util.HashMap::new()();
	    	 	for (var fieldName in object) {
	    	 		// Not sure whether this could really happen
	    	 		if(!$wnd.isA.String(fieldName)){
	    	 			continue;
	    	 		}
                    //if the field name is '__ref', the the value is already a GWT ajva object reference
	    	 		var convertedVal = fieldName == '__ref' ? object[fieldName] : $wnd.SmartGWT.convertToJavaObject(object[fieldName]);
 					@com.smartgwt.client.util.JSOHelper::doAddToMap(Ljava/util/Map;Ljava/lang/String;Ljava/lang/Object;)(javaMap, fieldName, convertedVal);
	    	 	}
	    	 	return javaMap;
	    	 }
        };


        $wnd.isc.RPCManager.__fireReplyCallback = $wnd.isc.RPCManager.fireReplyCallback;
        $wnd.isc.RPCManager.fireReplyCallback = function (callback, request, response, data) {
        	// convert primitives (number / bool) to Objects before firing callbacks
        	if (data != null && $wnd.isc.isA.Number(data) || $wnd.isc.isA.Boolean(data)) {
        	    data = response.data = $wnd.SmartGWT.convertToJavaType(data);
        	}
        	return this.__fireReplyCallback(callback, request, response, data);
        }
    }-*/;

    public void onModuleLoad() {
        //added boolean init check flag because GWT for some reason invokes this entry point class twice in hosted mode
        //even though it appears only once in the load hierarchy. Check with GWT team.
        if (!initialized) {
            LogUtil.setJSNIErrorHandler();
            init();
            I18nUtil.init();
            //set the default prompt style to a cursor
            RPCManager.setPromptStyle(PromptStyle.CURSOR);
            //install a default UEH that displays the error message in an alert when in development mode so that
            //is is not overlooked by the user during development
            GWT.setUncaughtExceptionHandler(new GWT.UncaughtExceptionHandler() {
                public void onUncaughtException(Throwable e) {
                    if (!GWT.isScript()) {
                        Window.alert("Uncaught exception escaped : " + e.getClass().getName() + "\n" + e.getMessage() +
                                "\nSee the Development console log for details." +
                                "\nRegister a GWT.setUncaughtExceptionHandler(..) for custom uncaught exception handling."
                        );
                    }
                    GWT.log("Uncaught exception escaped", e);
                }
            });
            initialized = true;
        }
    }
}
