package com.bc.horizon.fuzzing.sanitizer.handler;

import com.bc.horizon.fuzzing.sanitizer.annotation.Hook;
import com.bc.horizon.fuzzing.sanitizer.annotation.HookType;
import com.bc.horizon.fuzzing.sanitizer.annotation.Hooks;
import com.bc.horizon.fuzzing.sanitizer.model.Result;

import java.util.Arrays;

@Hooks(
        value = {
                @Hook(type = HookType.before, targetMethod = "<init>", targetClass = "java.io.File"),
                @Hook(type = HookType.before, targetMethod = "<init>", targetClass = "java.io.FileOutputStream"),
                @Hook(type = HookType.before, targetMethod = "<init>", targetClass = "java.io.FileInputStream")
        }
)
public class FileUploadSanitizerHandler implements ConstructorSanitizerHandler{
    @Override
    public Result handle(String className, String method, Object[] args, Integer methodLine, StackTraceElement[] stackTraceElements) {
        if(args.length > 0) {
            boolean flag = false;
            String filename = (String) args[0];
            String suffix=filename.substring(filename.lastIndexOf("."));
            String[] blacklist={".jsp",".php",".exe",".dll","vxd","html",".JSP",".PHP",".EXE",".DLL",".VXD","HTML"};//上传文件后缀名黑名单
            // {".jpg", ".png", ".jpeg", ".gif", ".bmp", ".ico"}白名单;
            for (String s : blacklist) {
                if (suffix.equals(s)){
                    flag = true;
                    break;
                }
            }
            if (flag) {
                if (stackTraceElements != null) {
                    for (StackTraceElement stackElement : stackTraceElements) {
                        System.out.println("at " + stackElement.getClassName()
                                + stackElement.getMethodName() + "(" + stackElement.getFileName() +
                                ":" + stackElement.getLineNumber() + ")");
                    }
                }

                return Result.builder()
                        .needRecord(true)
                        .exceptionMethod(method)
                        .exceptionClass(className)
                        .exceptionDesc("上传文件中包含恶意非法文件类型，建议对上传文件类型进行检查过滤！")
                        .requestParam(Arrays.toString(args))
                        .stackInfo(Arrays.toString(stackTraceElements))
                        .exceptionName("FileUpload Vulnerability")
                        .methodLine(methodLine)
                        .exceptionId("10")
                        .build();
            }

        }
        return Result.builder().needRecord(false).build();
    }
}
