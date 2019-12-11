package com.xiaohua.mybatisdemo.Realm;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;


public class UserRealm extends AuthorizingRealm {



    /**
     * 授权
     *
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {

//        //获取用户名
//        String username = principalCollection.getPrimaryPrincipal().toString();
//
//        //生成授权信息对象
//        SimpleAuthorizationInfo authenticationInfo = new SimpleAuthorizationInfo();
//        authenticationInfo.addRoles(iuser.getjiaose(username));
//        authenticationInfo.setStringPermissions(iuser.getquanx(username));
//
//
        return null;
    }


    /**
     * 认证
     *
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
//
//        // 通过authenticationToken获取传入的姓名
//        String userName = authenticationToken.getPrincipal().toString();
//        TSysUser user = iuser.select_name(userName);
//        if (ObjectUtils.isEmpty(user)) {
//            throw new UnknownAccountException("对不起！该用户不存在");
//        }
//
//        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(
//                user.getUsername(),
//                user.getPassword(),
//                this.getName()
//        );
//
       return null;
    }
}
