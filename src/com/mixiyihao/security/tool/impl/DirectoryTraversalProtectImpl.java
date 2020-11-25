package com.mixiyihao.security.tool.impl;

import com.mixiyihao.security.tool.DirectoryTraversalProtect;

import java.io.File;

public class DirectoryTraversalProtectImpl implements DirectoryTraversalProtect {




    @Override
    public String repairPathByfilterSpot(String relativePath) {
        if(relativePath == null ||relativePath.isEmpty()){
            return relativePath;
        }
        File file = new File(relativePath);
        String parentPath = file.getParent();
        // 如果传的是文件的话，那么对文件进行
        if(parentPath == null){
            return relativePath;
        }
        String replacePath = parentPath.replace(".", "");
        return new File(replacePath, file.getName()).toString();


    }


    @Override
    public boolean isSafeByRelativePath(String filePath) {
        if(filePath == null ||filePath.isEmpty()){
            return true;
        }
        //System.out.println(parent);
       return FileCheckUtil.doFilePathCheck(filePath);

    }




    public static void main(String args[]){
        DirectoryTraversalProtect dtp = new DirectoryTraversalProtectImpl();
        String path = "./....windows/win...ini";
        path = "../../windows/win.ini";

        String filedPath = dtp.repairPathByfilterSpot(path);
        boolean safeByRelativePath = dtp.isSafeByRelativePath(path);
        System.out.println(path+"---->"+safeByRelativePath);
        System.out.println(path+ "---->"+filedPath);

    }
}
