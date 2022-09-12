package com.bc.horizon.fuzzing.sanitizer.annotation;

import java.lang.annotation.*;

/**
 * <p>DESC: </p >
 * <p>DATE: 2022/6/28 0028</p >
 * <p>VERSION:</p >
 * <p>@AUTHOR: DengC</p >
 */
@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Hooks {
    Hook[] value();
}
