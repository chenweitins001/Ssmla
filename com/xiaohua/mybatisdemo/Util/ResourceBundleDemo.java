package com.xiaohua.mybatisdemo.Util;

import java.text.MessageFormat;
import java.util.Locale;
import java.util.ResourceBundle;

public class ResourceBundleDemo {

    public static void main(String[] args) {

        String path = "i18n";

        //根据默认地区得到name的值
        ResourceBundle re = ResourceBundle.getBundle(path);
        String rr = re.getString("name");
        System.out.println(rr);

        //自己设置地区获取值
        ResourceBundle rs = ResourceBundle.getBundle(path, Locale.US);
        String rw = rs.getString("name");
        System.out.println(rw);

        //复合字符

        String a = re.getString("aa");
        a = MessageFormat.format(a, "星狗", "啦啦啦");
        System.out.println(a);

        String b = rs.getString("aa");
        b = MessageFormat.format(b, "星狗", "啦啦啦");
        System.out.println(b);


    }
}
