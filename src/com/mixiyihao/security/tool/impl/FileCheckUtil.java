package com.mixiyihao.security.tool.impl;

import java.io.File;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FileCheckUtil {
    private static final Pattern PERCENTS_PAT = Pattern.compile("(%)([0-9a-fA-F])([0-9a-fA-F])");
    private static final Pattern FILE_BLACKLIST_PAT = Pattern.compile("([\\\\/:*?<>|^])");
    private static final Pattern DIR_BLACKLIST_PAT = Pattern.compile("([\\.*?<>|^])");

    public static void doDirCheck(String path) throws ValidationException {
        Matcher m1 = DIR_BLACKLIST_PAT.matcher( path );
        if ( null != m1 && m1.find() ) {
            throw new ValidationException( "Invalid directory", "Directory path (" + path + ") contains illegal character: " + m1.group() );
        }

        Matcher m2 = PERCENTS_PAT.matcher( path );
        if (null != m2 &&  m2.find() ) {
            throw new ValidationException( "Invalid directory", "Directory path (" + path + ") contains encoded characters: " + m2.group() );
        }

        int ch = containsUnprintableCharacters(path);
        if (ch != -1) {
            throw new ValidationException("Invalid directory", "Directory path (" + path + ") contains unprintable character: " + ch);
        }
    }

    public static void doFileCheck(String path) throws ValidationException {
        Matcher m1 = FILE_BLACKLIST_PAT.matcher( path );
        if ( m1.find() ) {
            throw new ValidationException( "Invalid directory", "Directory path (" + path + ") contains illegal character: " + m1.group() );
        }

        Matcher m2 = PERCENTS_PAT.matcher( path );
        if ( m2.find() ) {
            throw new ValidationException( "Invalid file", "File path (" + path + ") contains encoded characters: " + m2.group() );
        }
        int ch = containsUnprintableCharacters(path);
        if (ch != -1) {
            throw new ValidationException("Invalid file", "File path (" + path + ") contains unprintable character: " + ch);
        }
    }

    public static boolean doFilePathCheck(String filepath){
        if(filepath == null||filepath.isEmpty()){
            return true;
        }
        try {
            File file = new File(filepath);
            if (file.getParent() != null) {
                doDirCheck(file.getParent());
            }
            doFileCheck(file.getName());
            return true;
        }catch (Exception e){
            e.printStackTrace();
        }
        return false;
    }


    private static int containsUnprintableCharacters(String s) {
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (((int) ch) < 32 || ((int) ch) > 126) {
                return (int) ch;
            }
        }
        return -1;
    }

    public static String getUUID(){
        UUID uuid = UUID.randomUUID();
        String strUUid = uuid.toString();
        return strUUid.replaceAll("-","");
    }

    /**
     * 重命名
     * @param filepath 文件路径
     * @return
     */
    public static String renameFile(String filepath){
        File file = new File(filepath);
        String parent = file.getParent();
        String filename = file.getName();
        String tmpFileName = null;
       if(filepath.contains(".")) {
           int lastIndexof = filename.lastIndexOf(".");
           //System.out.println(lastIndexof);
           tmpFileName = getUUID() + filename.substring(lastIndexof, filename.length());

       }else{
           tmpFileName = getUUID();
       }
       // System.out.println(tmpFileName);
       return new File(parent, tmpFileName).toString();
    }

    public static void main(String[] args) {
        System.out.println(renameFile("bb/<test>.png"));
    }
}

