 package com.xiaohua.mybatisdemo.Util;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

 /**
  * @author Administrator
  * @create 2019-11-1210:39
  */
 @Component
 public class RedisCacheTransfer {

     @Autowired
     public void setRedisTemplate(RedisTemplate<String, Object> redisTemplate) {
         RedisCache.setRedisTemplate(redisTemplate);
     }

 }
