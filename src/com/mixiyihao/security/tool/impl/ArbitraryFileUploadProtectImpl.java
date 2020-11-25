package com.mixiyihao.security.tool.impl;


import com.mixiyihao.security.tool.ArbitraryFileUploadProtect;

public class ArbitraryFileUploadProtectImpl implements ArbitraryFileUploadProtect {




    /**
     * 检测文件类型
     * @param type
     * @param filepath
     * @return
     */
    private String checkWhilteListFormat(Type type, String filepath){
        String formats[] = null;
        switch (type){
            case IMAGE:
                formats = whiteListByImageFormat;
                break;
            case VEDIO:
                formats = whiteListByVedioFormat;
                break;
            case FILE:
                formats = whiteListByFileFormat;
                break;
        }
        for(String format: formats){
            if(filepath.endsWith(format)){
                return format;
            }
        }
        return null;

    }


    private String renameFile(String fileFormat){
        String uuid = FileCheckUtil.getUUID();
        return uuid +"."+ fileFormat;
    }

    public String checkFileByFile(String filepath, boolean renameFileName) {
        String refilename = null;
        String format = checkWhilteListFormat(Type.IMAGE, filepath);
        if(format == null){
            return null;
        }
        if(checkFile(filepath)){
            return filepath;
        }
        return null;
    }


    @Override
    public boolean checkFile(String filepath, Type type) {
        if(checkWhilteListFormat(type, filepath) == null){
            return false;
        }
        return checkFile(filepath);

    }

    @Override
    public boolean checkFile(String filename) {
        if(filename == null || filename.isEmpty()){
            return true;
        }

        return FileCheckUtil.doFilePathCheck(filename);
    }

    @Override
    public String checkFileAndReNameFile(String filepath, Type type) {
        boolean checkFile = checkFile(filepath, type);
        if(checkFile){
            return FileCheckUtil.renameFile(filepath);
        }
        return null;
    }


    public static void main(String[] args) {
        ArbitraryFileUploadProtect aup = new ArbitraryFileUploadProtectImpl();
        boolean result = aup.checkFile("");
        System.out.println(result);
        result = aup.checkFile(".", Type.VEDIO);
        System.out.println(result);
    }
}
