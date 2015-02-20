force-authentication
====================

Spring-based Salesforce authentication that works with canvas signed requests, HTTP headers, or OAuth.

# Building

The project is built using gradle. The project includes the standard `gradlew` wrapper that does all the heavy lifting. `gradlew` makes sure the right version of gradle is available so that you don't need to worry about  installing it yourself. It is all automatic. To build, just type:
   ```bash
./gradlew
   ```

# Sample Spring Configuration
This library is designed to work with Spring authentication. You simply configure the library's Spring Beans into your 
application and then the library does the rest. A spring bean called **oAuthClientConfig** is exposed for configuring 
the details of your Salesforce oauth application. Below is an example Spring configuration. This particular example
leverages Spring's **PropertySourcesPlaceholderConfigurer** to accept OAUTH configuration from the environment.

    <!-- Detect and autowire annotated components -->
    <context:annotation-config/>
    <context:component-scan base-package="net.davidbuccola.force.authentication"/>

    <!-- Configurable values which can be overridden in the servlet properties, system properties, or environment. -->
    <bean id="propertyConfigurer" class="org.springframework.context.support.PropertySourcesPlaceholderConfigurer">
        <property name="properties">
            <props>
                <prop key="FORCE_SERVER_URL">https://login.salesforce.com</prop>
                <prop key="FORCE_CLIENT_ID"/>
                <prop key="FORCE_CLIENT_SECRET"/>
                <prop key="FORCE_DISPLAY"/>
                <prop key="FORCE_PROMPT"/>
            </props>
        </property>
    </bean>

    <!-- Salesforce OAuth Configuration -->
    <bean id="oAuthClientConfig" class="net.davidbuccola.force.authentication.SpringOAuthClientConfig">
        <property name="serverURL" value="${FORCE_SERVER_URL}"/>
        <property name="clientId" value="${FORCE_CLIENT_ID}"/>
        <property name="clientSecret" value="${FORCE_CLIENT_SECRET}"/>
        <property name="display" value="${FORCE_DISPLAY}"/>
        <property name="prompt" value="${FORCE_PROMPT}"/>
    </bean>

    <!-- Spring Security Configuration -->
    <security:authentication-manager/>
    <security:http auto-config="false" entry-point-ref="authenticationEntryPoint" use-expressions="true">
        <security:custom-filter ref="signedRequestFilter" position="BASIC_AUTH_FILTER"/>
        <security:custom-filter ref="oAuthFilter" after="BASIC_AUTH_FILTER"/>
        <security:intercept-url pattern="/api/**" access="hasRole('ROLE_API_USER')"/>
        <security:intercept-url pattern="/canvas" access="hasRole('ROLE_CANVAS_USER')"/>
        <security:intercept-url pattern="/favicon.ico" access="permitAll"/>
        <security:intercept-url pattern="/webjars/**" access="permitAll"/>
        <security:intercept-url pattern="/exp/**" access="permitAll"/>
        <security:intercept-url pattern="/**" access="hasRole('ROLE_USER')"/>
    </security:http>

