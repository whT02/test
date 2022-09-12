package com.bc.horizon.fuzzing.sanitizer.handler;

import com.bc.horizon.fuzzing.sanitizer.annotation.Hook;
import com.bc.horizon.fuzzing.sanitizer.annotation.HookType;
import com.bc.horizon.fuzzing.sanitizer.annotation.Hooks;
import com.bc.horizon.fuzzing.sanitizer.model.Result;
import org.apache.commons.lang3.StringUtils;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Arrays;

@Hooks(
        value = {
                @Hook(type = HookType.before, targetMethod = "<init>", targetClass = "java.net.URL")
        }
)
public class SSRFSanitizerHandler implements ConstructorSanitizerHandler{
    @Override
    public Result handle(String className, String method, Object[] args, Integer methodLine, StackTraceElement[] stackTraceElements) {
        if (args.length > 0){
            String request = (String) args[0];
            boolean flag = false; //判断网址是否为http/https协议
            boolean check = false;//判断网址是否可重定向

            check = isredirect(request,2);
            //截取常见跳转关键字后的网址,判断其是否为http/https以外的协议
            if (request.contains("url")){
                String url = StringUtils.substringAfter(request, "?url=");
                flag = isnohttp(url);
            } else if(request.contains("redirect")){
                String url = StringUtils.substringAfter(request, "?redirect=");
                flag = isnohttp(url);
            }else if(request.contains("jump")){
                String url = StringUtils.substringAfter(request, "?jump=");
                flag = isnohttp(url);
            }
            else if(request.contains("link")){
                String url = StringUtils.substringAfter(request, "?link=");
                flag = isnohttp(url);
            }
            else if(request.contains("target")){
                String url = StringUtils.substringAfter(request, "?target=");
                flag = isnohttp(url);
            }
            else if(request.contains("redirect_url")){
                String url = StringUtils.substringAfter(request, "?redirect_url=");
                flag = isnohttp(url);
            }

            if (flag || check){
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
                        .exceptionDesc("初始化连接的URl中存在非http/http协议，可能通过file://等协议造成文件泄露，或初始化url中包含重定向网址，可能存在SSRF漏洞，建议对载入url实现白名单监测！")
                        .requestParam(Arrays.toString(args))
                        .stackInfo(Arrays.toString(stackTraceElements))
                        .exceptionName("SSRF Injection")
                        .methodLine(methodLine)
                        .exceptionId("11")
                        .build();
            }

        }
        return Result.builder().needRecord(false).build();
    }
    //判断是否为http/https以外的其他协议
    private boolean isnohttp(String url){
        boolean flag = false;
        if(!url.startsWith("http") && !url.startsWith("https")){
            flag = true;
        }
        return flag;
    }

    //判断是否为可重定向的url
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
