package com.bc.horizon.fuzzing.sanitizer.handler;

import com.bc.horizon.fuzzing.sanitizer.annotation.Hook;
import com.bc.horizon.fuzzing.sanitizer.annotation.HookType;
import com.bc.horizon.fuzzing.sanitizer.annotation.Hooks;
import com.bc.horizon.fuzzing.sanitizer.model.Result;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Arrays;

@Hooks(
        value = {
                @Hook(type = HookType.before, targetMethod = "<init>", targetClass = "java.net.URL")
        }
)
public class UrlRedirectSanitizerHandler implements ConstructorSanitizerHandler{
    @Override
    public Result handle(String className, String method, Object[] args, Integer methodLine, StackTraceElement[] stackTraceElements) {
        if (args.length > 0) {
            String request = (String) args[0];
            boolean check = false;//判断网址是否可重定向
            check = isredirect(request, 2);

            if (check){
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
                        .exceptionDesc("初始化url可重定向其他网址，可能存在URL重定向漏洞，建议对载入url设置白名单！")
                        .requestParam(Arrays.toString(args))
                        .stackInfo(Arrays.toString(stackTraceElements))
                        .exceptionName("URL Redirect")
                        .methodLine(methodLine)
                        .exceptionId("12")
                        .build();
            }
        }
        return Result.builder().needRecord(false).build();
    }
    private boolean isredirect(String url, int checkTimes) {
        HttpURLConnection connection;
        int connectTime = 5 * 1000;  // 设置连接超时时间5s
        int i = 1;
        String finalUrl = url;
        boolean check = false;
        try {
            do {
                connection = (HttpURLConnection) new URL(finalUrl).openConnection();
                connection.setInstanceFollowRedirects(false);
                connection.setUseCaches(false);
                connection.setConnectTimeout(connectTime);
                connection.connect();
                int responseCode = connection.getResponseCode(); // 获得网络请求状态码
                if (responseCode >= 300 && responseCode <= 307 && responseCode != 304 && responseCode != 306) {
                    String redirectedUrl = connection.getHeaderField("Location");
                    if (null == redirectedUrl)
                        break;
                    finalUrl = redirectedUrl;
                    i += 1;  // 重定向次数加1
                    //System.out.println("redirected url: " + finalUrl);
                    if (i == checkTimes) {
                        check = true;  //重定向url,返回true
                    }
                } else
                    break;
            } while (connection.getResponseCode() != HttpURLConnection.HTTP_OK);
            connection.disconnect();
        } catch (Exception e) {
            return check;  // 有异常说明不能重定向，返回false
        }
        return check;
    }
}
