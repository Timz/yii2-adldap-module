<?php
include_once ('base\TestVariables.php');

require_once(__DIR__ . '/../../../../models/LoginForm.php');
use app\models\LoginForm;

class UserModelTest extends TestCase
{   
    // after each test clear
    public function tearDown() {
        \Yii::$app->db->createCommand()->truncateTable("auth_assignment")->execute();
        \Yii::$app->db->createCommand()->truncateTable("user")->execute();
        parent::tearDown();
    }
    
    // before each test clear
    public function setUp() {
        parent::setUp();
        \Yii::$app->db->createCommand()->truncateTable("auth_assignment")->execute();
        \Yii::$app->db->createCommand()->truncateTable("user")->execute();
    }
    
    // generic function to create user model used by test functions
    private function getNewUserModel() {
        $ldapmodel = new migcredit\Adldap2\model\UserDbLdap();
        $ldapmodel->username = TestVariables::$TEST_USER_ACCOUNT_NAME;
        return $ldapmodel;
    }
    
    // test if queryLdapUserObject works
    public function testQueryLdapUserObject() {
        $userObject = $this->getNewUserModel()->queryLdapUserObject();
        $this->assertEquals($userObject['attributes']['givenname'][0],TestVariables::$TEST_USER_GIVEN_NAME,'Key givenname not found!'); //Givenname is same as defined             
    }
    
    // test if group is added to user
    public function testQueryLdapUserGroupMembership() {
        $groups = $this->getNewUserModel()->getGroupsAssignedInLdap();
        $this->assertContains(TestVariables::$TEST_GROUP_NAME, $groups,'Group ' . TestVariables::$TEST_GROUP_NAME . ' is missing!');
    }
    
    // test if a query with a disabled username returns null
    public function testFindByUsernameDisabledUser() {
        $userObject = migcredit\Adldap2\model\UserDbLdap::findByUsername(TestVariables::$TEST_DISABLED_USER);

        $this->assertNull($userObject,'A disabled user cannot be returned by findByUsername');
    }
    
    // test if findByUsername returns the user
    public function testFindByUsername() {
        $userObject = migcredit\Adldap2\model\UserDbLdap::findByUsername(TestVariables::$TEST_USER_ACCOUNT_NAME);
        $userName = $userObject->queryLdapUserObject()['attributes']['samaccountname'][0];
        
        $this->assertEquals($userName,TestVariables::$TEST_USER_ACCOUNT_NAME,'No correct instance of the test user ' . TestVariables::$TEST_USER_ACCOUNT_NAME . ' returned by findByUsername');
    }     
    
    // test if query a non existing user id returns null
    public function testFindIdentityNotExistingUserId() {
        $userObject = migcredit\Adldap2\model\UserDbLdap::findIdentity(9999);

        $this->assertNull($userObject,'Not existing identity cannot be found!');
    }
    
    // test if user is found by id
    public function testFindIdentityWithId() {
        $userObject = migcredit\Adldap2\model\UserDbLdap::findByUsername(TestVariables::$TEST_USER_ACCOUNT_NAME);
        $userObjectById = migcredit\Adldap2\model\UserDbLdap::findIdentity($userObject->getId());

        $userName = $userObjectById->queryLdapUserObject()['attributes']['samaccountname'][0];
        
        $this->assertEquals($userName,TestVariables::$TEST_USER_ACCOUNT_NAME,'No correct instance of the test user ' . TestVariables::$TEST_USER_ACCOUNT_NAME . ' returned by findByUsername');
    }
    
    // test a disabled user
    public function testUpdateAccountStatus() {
        $userObject = migcredit\Adldap2\model\UserDbLdap::findByUsername(TestVariables::$TEST_USER_ACCOUNT_NAME);
        $userObject->status = migcredit\Adldap2\model\UserDbLdap::STATUS_DISABLED;
        $userObject->save();
        
        $this->assertEquals($userObject->status,migcredit\Adldap2\model\UserDbLdap::STATUS_DISABLED, 'User should be disabled.');
        $userObject->updateAccountStatus();
        
        $this->assertEquals($userObject->status,migcredit\Adldap2\model\UserDbLdap::STATUS_ENABLED, 'User should be reenabled after updateAccountStatus.');
    }

    public function testCheckAllowedToLoginWithNullUser() {
        $userObject = migcredit\Adldap2\model\UserDbLdap::findByUsername('NOTEXISTINGACCOUNT');
        $userObject2 = migcredit\Adldap2\model\UserDbLdap::checkAllowedToLogin($userObject);
        
        $this->assertEquals($userObject,$userObject2, 'The object returned for a successfull login by checkAllowedToLogin has to be euqal to the instance given as parameter');
    }   
    
    public function testCheckAllowedToLogin() {
        $userObject = migcredit\Adldap2\model\UserDbLdap::findByUsername(TestVariables::$TEST_USER_ACCOUNT_NAME);
        $userObject2 = migcredit\Adldap2\model\UserDbLdap::checkAllowedToLogin($userObject);
        
        $this->assertEquals($userObject,$userObject2, 'The object returned for a successfull login by checkAllowedToLogin has to be euqal to the instance given as parameter');
    }
    
    public function testUpdateGroupAssignment() {
        $auth = Yii::$app->authManager;
        
        if(is_null($auth->getPermission('permissionTestUnit'))) {
            // add "permissionToUseContanctPage" permission
            $permTestUnit = $auth->createPermission('permissionTestUnit');
            $permTestUnit->description = 'Permission autocreated from test unit';
            $auth->add($permTestUnit);
        }
        
        if(is_null($auth->getRole(TestVariables::$TEST_GROUP_NAME))) {
            // add "yii2_see_home_group" role and give this role the "permissionToSeeHome" permission
            $yii2RoleTestGroup = $auth->createRole(TestVariables::$TEST_GROUP_NAME);
            $auth->add($yii2RoleTestGroup);
            $auth->addChild($yii2RoleTestGroup, $permTestUnit);         
        }
        
        $userObject = migcredit\Adldap2\model\UserDbLdap::findByUsername(TestVariables::$TEST_USER_ACCOUNT_NAME);
        $yiiRolesAssignedToUser = Yii::$app->authManager->getRolesByUser($userObject->getId()); //Get all roles assigned to user
        
        //User has only group yii2_example_group assinged.
        $this->assertArrayHasKey(TestVariables::$TEST_GROUP_NAME,$yiiRolesAssignedToUser,'Role ' . TestVariables::$TEST_GROUP_NAME . ' has to be assigned.');
        $this->assertArrayNotHasKey(TestVariables::$TEST_NESTED_GROUP_NAME,$yiiRolesAssignedToUser,'Nested group ' . TestVariables::$TEST_NESTED_GROUP_NAME . ' has NOT to be assigned.');
        
        //Search for nested groups
        $userObject->setIndividualGroupAssignmentOptions(
                ['SEARCH_NESTED_GROUPS' => true]
                );
        
        //Test nested Group search. 
        //Nested group cannot bes assigned to user beacause no role in yii2 exists.
        $groupsPossible = $userObject->getGroupsAssignedInLdap();
        
        $this->assertContains(TestVariables::$TEST_GROUP_NAME,$groupsPossible,'Group ' . TestVariables::$TEST_GROUP_NAME . ' has to be found in AD.');
        $this->assertContains(TestVariables::$TEST_NESTED_GROUP_NAME,$groupsPossible,'Nested group ' . TestVariables::$TEST_NESTED_GROUP_NAME . ' has to be found in AD.');
    }    
    
    public function testFindByAttribute() {
        //A query with more than one result sould return null
        $userObject = migcredit\Adldap2\model\UserDbLdap::findByAttribute('countryCode',0);
        $this->assertNull($userObject,'A attribute which is not suitable for unique identification should return null');       
        
        $userObject = migcredit\Adldap2\model\UserDbLdap::findByAttribute('displayName',TestVariables::$TEST_USER_DISPLAY_NAME);
        $userName = $userObject->queryLdapUserObject()['attributes']['samaccountname'][0];
        
        $userObject = migcredit\Adldap2\model\UserDbLdap::findByAttribute('samaccountname',TestVariables::$TEST_USER_ACCOUNT_NAME);
        $userName = $userObject->queryLdapUserObject()['attributes']['samaccountname'][0];
        
        $this->assertEquals($userName,TestVariables::$TEST_USER_ACCOUNT_NAME,'No correct instance of the test user ' . TestVariables::$TEST_USER_ACCOUNT_NAME . ' returned by findByUsername');        
    }
    
    /**
     * @runInSeparateProcess
     */    
    public function testUserTestLogin() {
        $model = new LoginForm();
        
        //Test a real login
        $this->assertTrue($model->load(['LoginForm'=> ['username' => TestVariables::$TEST_USER_ACCOUNT_NAME, 'password' => TestConfig::$TEST_USER_PASSWORD]]),'Load data into model failed');
        $this->assertTrue($model->login(),'Login with LDAP failed');
        $this->assertFalse(Yii::$app->user->isGuest,'User is not logged in');
        
        //Save id
        $idOfUser = Yii::$app->user->getId();      
        
        //Simulate a request after a successfull Login
        $userObjectById = migcredit\Adldap2\model\UserDbLdap::findIdentity($idOfUser);
        $userName = $userObjectById->queryLdapUserObject()['attributes']['samaccountname'][0];
        $this->assertEquals($userName,TestVariables::$TEST_USER_ACCOUNT_NAME,'No correct instance of the test user ' . TestVariables::$TEST_USER_ACCOUNT_NAME . ' returned by queryLdapUserObject');
        
        //Logout
        Yii::$app->user->logout();
        $this->assertTrue(Yii::$app->user->isGuest,'User is not a guest');
        
        //Try a second login
        $this->assertTrue($model->load(['LoginForm'=> ['username' => TestVariables::$TEST_USER_ACCOUNT_NAME, 'password' => TestConfig::$TEST_USER_PASSWORD]]),'Load data into model failed');
        $this->assertTrue($model->login(),'Login with LDAP failed');
        
        //Try permissions
        $this->assertTrue(Yii::$app->user->can('permissionTestUnit'),'Permission cannot be found');
    }
    
    public function testCleanup() {
        $this->assertTrue($this->checkAndDeleteUser());
    }  
}
