package com.xiaohua.mybatisdemo.Util;

import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.session.SqlSessionFactoryBuilder;

import java.io.InputStream;

public class MybatisSessionFactoryUtils {

	public static SqlSessionFactory sqlSessionFactory;

	private static ThreadLocal<SqlSession> threadLocal = new ThreadLocal<SqlSession>();

	static {
		try {
			InputStream is = MybatisSessionFactoryUtils.class
					.getResourceAsStream("/mybatis.cfg.xml");
			SqlSessionFactoryBuilder sqlSessionFactoryBuilder = new SqlSessionFactoryBuilder();
			sqlSessionFactory = sqlSessionFactoryBuilder.build(is);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private MybatisSessionFactoryUtils() {
	}

	public static SqlSession openSession() {
		SqlSession sqlSession = threadLocal.get();
		if (null == sqlSession) {
			sqlSession = sqlSessionFactory.openSession();
			threadLocal.set(sqlSession);
		}
		return sqlSession;
	}

	public static void closeSession() {
		SqlSession sqlSession = threadLocal.get();
		if (null != sqlSession) {
			threadLocal.set(null);
			sqlSession.close();
		}
	}
	
	public static void main(String[] args) {
		SqlSession sqlSession = MybatisSessionFactoryUtils.openSession();
		System.out.println(sqlSession);
		System.out.println(sqlSession.getConnection());
		MybatisSessionFactoryUtils.closeSession();
	}

}
