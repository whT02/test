package com.bc.horizon.fuzzing.sanitizer.handler;

import com.bc.horizon.fuzzing.sanitizer.annotation.Hook;
import com.bc.horizon.fuzzing.sanitizer.annotation.HookType;
import com.bc.horizon.fuzzing.sanitizer.annotation.Hooks;
import com.bc.horizon.fuzzing.sanitizer.model.Result;

import java.lang.reflect.Method;

@Hooks(
        value = {
                @Hook(type = HookType.before, targetMethod = "readObject", targetClass = "javax.io.ObjectInputStream"),
                @Hook(type = HookType.before, targetMethod = "readObjectOverride", targetClass = "javax.io.ObjectInputStream"),
                @Hook(type = HookType.before, targetMethod = "readUnshared", targetClass = "javax.io.ObjectInputStream")

        }
)

public class DeserializationSanitizerHandler implements SanitizerHandler{
    @Override
    public Result handle(Method method, Object[] args, Integer methodLine, StackTraceElement[] stackTraceElements) {
        return null;
    }
}
