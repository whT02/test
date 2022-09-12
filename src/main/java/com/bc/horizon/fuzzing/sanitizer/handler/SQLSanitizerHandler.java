package com.bc.horizon.fuzzing.sanitizer.handler;

import com.bc.horizon.fuzzing.sanitizer.annotation.Hook;
import com.bc.horizon.fuzzing.sanitizer.annotation.HookType;
import com.bc.horizon.fuzzing.sanitizer.annotation.Hooks;
import com.bc.horizon.fuzzing.sanitizer.model.Result;
import net.sf.jsqlparser.JSQLParserException;
import net.sf.jsqlparser.parser.CCJSqlParserUtil;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;

@Hooks(
        value = {
                @Hook(type = HookType.before, targetMethod = "execute", targetClass = "java.sql.Statement"),
                @Hook(type = HookType.before, targetMethod = "executeBatch", targetClass = "java.sql.Statement"),
                @Hook(type = HookType.before, targetMethod = "executeLargeBatch", targetClass = "java.sql.Statement"),
                @Hook(type = HookType.before, targetMethod = "executeLargeUpdate", targetClass = "java.sql.Statement"),
                @Hook(type = HookType.before, targetMethod = "executeQuery", targetClass = "java.sql.Statement"),
                @Hook(type = HookType.before, targetMethod = "executeUpdate", targetClass = "java.sql.Statement"),
                @Hook(type = HookType.before, targetMethod = "createNativeQuery", targetClass = "javax.persistence.EntityManager"),
        }
)
public class SQLSanitizerHandler implements SanitizerHandler{
    @Override
    public Result handle(Method method, Object[] args, Integer methodLine, StackTraceElement[] stackTraceElements) {
        System.out.println("method=" + method);//测试是否触发到目标方法

        boolean hasValidSqlQuery;

        ArrayList<String> list = new ArrayList<>();
        //查询中要转义的字符
        String FILTER_CHARACTERS = "'、\"、b、n、r、t、z、%、_、\\、";
        String[] result = FILTER_CHARACTERS.split("、");

        if (args.length > 0) {
            String query = (String) args[0];
            hasValidSqlQuery = isValidSql(query);

            for (String s : result) {
                list.add(String.valueOf(query.contains(s)));
            }

            if (!hasValidSqlQuery && list.contains("true")){
                if (stackTraceElements != null) {
                    for (StackTraceElement stackElement : stackTraceElements) {
                        System.out.println("at " + stackElement.getClassName()
                                + stackElement.getMethodName() + "(" + stackElement.getFileName() +
                                ":" + stackElement.getLineNumber() + ")");
                    }
                }
                return Result.builder()
                        .needRecord(true)
                        .exceptionMethod(method.getName())
                        .exceptionClass(method.getDeclaringClass().getName())
                        .exceptionDesc("SQL执行语句中包含未转义的特殊字符，可能存在SQL注入风险，建议对特殊字符实现反斜杠转义操作！")
                        .requestParam(Arrays.toString(args))
                        .stackInfo(Arrays.toString(stackTraceElements))
                        .exceptionName("SQL Injection")
                        .methodLine(methodLine)
                        .exceptionId("9")
                        .build();
            }
        }
        return Result.builder().needRecord(false).build();
    }

    private Boolean isValidSql(String sql){
        boolean flag;
        try {
            CCJSqlParserUtil.parseStatements(sql);
            flag = true;
        }
        catch (JSQLParserException exception) { flag = false;}
        catch (Throwable throwable) { throwable.printStackTrace(); flag = true;}
        return flag;
    }

}
