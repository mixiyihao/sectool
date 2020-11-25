package com.mixiyihao.security.tool.impl;

import com.mixiyihao.security.tool.XXEProtect;
import org.dom4j.io.SAXReader;
import org.jdom2.input.SAXBuilder;
import org.xml.sax.SAXException;
import org.xml.sax.SAXNotRecognizedException;
import org.xml.sax.SAXNotSupportedException;
import org.xml.sax.XMLReader;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.sax.SAXTransformerFactory;
import javax.xml.validation.SchemaFactory;


public class XXEProtectImpl  implements XXEProtect {



    @Override
    public boolean repaireXXE(Object object) {
        if(object == null){
            throw new NullPointerException("object 为空");
        }
        if(object instanceof DocumentBuilderFactory){
            try {
                DocumentBuilderFactory dbf = (DocumentBuilderFactory)object;
                String FEATURE = "http://javax.xml.XMLConstants/feature/secure-processing";
                dbf.setFeature(FEATURE, true);
                FEATURE = "http://apache.org/xml/features/disallow-doctype-decl";
                dbf.setFeature(FEATURE, true);
                FEATURE = "http://xml.org/sax/features/external-parameter-entities";
                dbf.setFeature(FEATURE, false);
                FEATURE = "http://xml.org/sax/features/external-general-entities";
                dbf.setFeature(FEATURE, false);
                FEATURE = "http://apache.org/xml/features/nonvalidating/load-external-dtd";
                dbf.setFeature(FEATURE, false);
                dbf.setXIncludeAware(false);
                dbf.setExpandEntityReferences(false);
                return true;
            } catch (Exception e) {
                e.printStackTrace();
            }

        }else if(object instanceof SAXParserFactory){
            try {
                SAXParserFactory spf = (SAXParserFactory) object;
                spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
                spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
                spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
                spf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
                return true;
            }catch (Exception e){
                e.printStackTrace();
            }
        }else if(object instanceof SAXTransformerFactory){
            SAXTransformerFactory sff = (SAXTransformerFactory) object;
            sff.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            sff.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        }else if(object instanceof SAXBuilder){
            SAXBuilder saxBuilder = (SAXBuilder)object;
            saxBuilder.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            saxBuilder.setFeature("http://xml.org/sax/features/external-general-entities", false);
            saxBuilder.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            saxBuilder.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            return true;
            //Objects.equals()

        }else if(object instanceof SAXReader){
            SAXReader saxReader = (SAXReader)object;
            try {
                saxReader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
                saxReader.setFeature("http://xml.org/sax/features/external-general-entities", false);
                saxReader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
                saxReader.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
                return true;
            } catch (SAXException e) {
                e.printStackTrace();
            }
        }else if(object instanceof SchemaFactory){
            SchemaFactory factory = (SchemaFactory)object;
            try {
                factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
                factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
                return true;
            } catch (SAXNotRecognizedException e) {
                e.printStackTrace();
            } catch (SAXNotSupportedException e) {
                e.printStackTrace();
            }
        }else if(object instanceof TransformerFactory){
            TransformerFactory tf = (TransformerFactory)object;
            tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
            return true;

        }else if(object instanceof XMLReader){
            XMLReader reader = (XMLReader)object;
            try {
                reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
                reader.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
                reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
                reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
                return true;
            } catch (SAXNotRecognizedException e) {
                e.printStackTrace();
            } catch (SAXNotSupportedException e) {
                e.printStackTrace();
            }
        }else{
            throw new IllegalArgumentException("未找到对象，请联系作者进行添加或者自己查找相关修复方案");
        }
        return false;

    }

    public static void main(String[] args) {
        XXEProtect xxeProtect = new XXEProtectImpl();
        xxeProtect.repaireXXE(null);
    }
}
