/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.sample.user.store.manager;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLTimeoutException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.user.api.Properties;
import org.wso2.carbon.user.api.Property;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.common.AuthenticationResult;
import org.wso2.carbon.user.core.common.FailureReason;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.common.UserUniqueIDManger;
import org.wso2.carbon.user.core.jdbc.JDBCRealmConstants;
import org.wso2.carbon.user.core.jdbc.UniqueIDJDBCUserStoreManager;
import org.wso2.carbon.user.core.profile.ProfileConfigurationManager;
import org.wso2.carbon.user.core.util.DatabaseUtil;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.dbcreator.DatabaseCreator;
import org.wso2.carbon.utils.xml.StringUtils;

/**
 * This class implements the Custom User Store Manager.
 */
public class CustomUserStoreManager extends UniqueIDJDBCUserStoreManager {

	private static final String MULTI_ATTRIBUTE_SEPARATOR = "MultiAttributeSeparator";

	private static final Log log = LogFactory.getLog(CustomUserStoreManager.class);

	public CustomUserStoreManager() {

	}

	public CustomUserStoreManager(RealmConfiguration realmConfig, Map<String, Object> properties,
			ClaimManager claimManager, ProfileConfigurationManager profileManager, UserRealm realm, Integer tenantId)
			throws UserStoreException {

		super(realmConfig, properties, claimManager, profileManager, realm, tenantId);
		log.info("CustomUserStoreManager initialized...");
	}

	/**
	 * It returns the digest value of a particular SHA-256 algorithm in the form of
	 * Byte Array.
	 *
	 * @param input The String password which needs to be hashed using the
	 *              particular algorithm.
	 * @return The byte array of hashed password.
	 * @throws NoSuchAlgorithmException //no such algorithm which is defined
	 */
	public static byte[] getSHA(String input) throws NoSuchAlgorithmException {

		MessageDigest md = MessageDigest.getInstance("SHA-256");
		return md.digest(input.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * Byte array has been converted into hex format to get the MessageDigest.
	 *
	 * @param hash Byte array which contains hashed password
	 * @return final hashed hexString
	 */
	public static String toHexString(byte[] hash) {

		BigInteger number = new BigInteger(1, hash);
		StringBuilder hexString = new StringBuilder(number.toString(16));
		while (hexString.length() < 32) {
			hexString.insert(0, '0');
		}
		return hexString.toString();
	}

	@Override
	public List<User> doListUsersWithID(String filter, int maxItemLimit) throws UserStoreException {

		List<User> users = new ArrayList<>();
		Connection dbConnection = null;
		String sqlStmt;
		PreparedStatement prepStmt = null;
		ResultSet rs = null;

		if (maxItemLimit == 0) {
			return Collections.emptyList();
		}

		int givenMax;
		try {
			givenMax = Integer
					.parseInt(realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_MAX_USER_LIST));
		} catch (NumberFormatException e) {
			givenMax = UserCoreConstants.MAX_USER_ROLE_LIST;
		}

		if (maxItemLimit < 0 || maxItemLimit > givenMax) {
			maxItemLimit = givenMax;
		}

		try {

			if (filter != null && filter.trim().length() != 0) {
				filter = filter.trim();
				filter = filter.replace("*", "%");
				filter = filter.replace("?", "_");
			} else {
				filter = "%";
			}

			List<User> userList = new ArrayList<>();

			dbConnection = getDBConnection();

			if (dbConnection == null) {
				throw new UserStoreException("Attempts to establish a connection with the data source has failed.");
			}
			sqlStmt = "SELECT UM_USER_ID,UM_USER_NAME FROM UM_USER WHERE UM_USER_NAME LIKE ? ORDER BY UM_USER_NAME";
			prepStmt = dbConnection.prepareStatement(sqlStmt);
			prepStmt.setString(1, filter);

			prepStmt.setMaxRows(maxItemLimit);

			try {
				rs = prepStmt.executeQuery();
			} catch (SQLException e) {
				if (e instanceof SQLTimeoutException) {
					log.error("The cause might be a time out. Hence ignored", e);
					return users;
				}
				String errorMessage = "Error while fetching users according to filter : " + filter
						+ " & max Item limit " + ": " + maxItemLimit;
				if (log.isDebugEnabled()) {
					log.debug(errorMessage, e);
				}
				throw new UserStoreException(errorMessage, e);
			}

			while (rs.next()) {
				String userID = rs.getString(1);
				String userName = rs.getString(2);
				if (CarbonConstants.REGISTRY_ANONNYMOUS_USERNAME.equals(userID)) {
					continue;
				}

				User user = getUser(userID, userName);
				userList.add(user);
			}
			rs.close();

			if (!userList.isEmpty()) {
				users = userList;
			}

		} catch (SQLException e) {
			String msg = "Error occurred while retrieving users for filter : " + filter + " & max Item limit : "
					+ maxItemLimit;
			if (log.isDebugEnabled()) {
				log.debug(msg, e);
			}
			throw new UserStoreException(msg, e);
		} finally {
			DatabaseUtil.closeAllConnections(dbConnection, rs, prepStmt);
		}

		return users;
	}

	@Override
	public org.wso2.carbon.user.api.Properties getDefaultUserStoreProperties() {

		Properties properties = new Properties();

		properties.setMandatoryProperties(
				CustomUserStoreConstants.CUSTOM_UM_MANDATORY_PROPERTIES.toArray(new Property[0]));
		properties
				.setOptionalProperties(CustomUserStoreConstants.CUSTOM_UM_OPTIONAL_PROPERTIES.toArray(new Property[0]));
		properties
				.setAdvancedProperties(CustomUserStoreConstants.CUSTOM_UM_ADVANCED_PROPERTIES.toArray(new Property[0]));
		return properties;
	}

	private AuthenticationResult getAuthenticationResult(String reason) {

		AuthenticationResult authenticationResult = new AuthenticationResult(
				AuthenticationResult.AuthenticationStatus.FAIL);
		authenticationResult.setFailureReason(new FailureReason(reason));
		return authenticationResult;
	}

	@Override
	protected AuthenticationResult doAuthenticateWithUserName(String userName, Object credential)
			throws UserStoreException {

		AuthenticationResult authenticationResult = new AuthenticationResult(
				AuthenticationResult.AuthenticationStatus.FAIL);
		User user;

		if (!isValidUserName(userName)) {
			String reason = "Username validation failed.";
			if (log.isDebugEnabled()) {
				log.debug(reason);
			}
			return getAuthenticationResult(reason);
		}

		if (UserCoreUtil.isRegistryAnnonymousUser(userName)) {
			String reason = "Anonymous user trying to login.";
			log.error(reason);
			return getAuthenticationResult(reason);
		}

		if (!isValidCredentials(credential)) {
			String reason = "Password validation failed.";
			if (log.isDebugEnabled()) {
				log.debug(reason);
			}
			return getAuthenticationResult(reason);
		}

		Connection dbConnection = null;
		ResultSet rs = null;
		PreparedStatement prepStmt = null;
		String sqlstmt;
		String password = null;
		boolean isAuthed = false;

		try {
			dbConnection = getDBConnection();
			dbConnection.setAutoCommit(false);

			sqlstmt = "SELECT UM_USER_ID,UM_USER_NAME,UM_USER_PASSWORD FROM UM_USER WHERE UM_USER_NAME=?";

			if (log.isDebugEnabled()) {
				log.debug(sqlstmt);
			}

			prepStmt = dbConnection.prepareStatement(sqlstmt);
			prepStmt.setString(1, userName);
			//String[] prpertyname = { "mobile" };

			rs = prepStmt.executeQuery();
			while (rs.next()) {
				String userID = rs.getString(1);
				String storedPassword = rs.getString(3);

				try {
					password = toHexString(getSHA(credential.toString()));
				} catch (NoSuchAlgorithmException e) {
					String msg = "Exception thrown for incorrect algorithm: SHA256 ";
					if (log.isDebugEnabled()) {
						log.debug(msg, e);
					}
				}
				if ((storedPassword != null) && (storedPassword.equals(password))) {
					isAuthed = true;
					user = getUser(userID, userName);
					//getUserPropertyValuesWithID(userID, prpertyname, userName);
					authenticationResult = new AuthenticationResult(AuthenticationResult.AuthenticationStatus.SUCCESS);
					authenticationResult.setAuthenticatedUser(user);

				}
			}

		} catch (SQLException e) {
			String msg = "Error occurred while retrieving user authentication info for userName : " + userName;
			if (log.isDebugEnabled()) {
				log.debug(msg, e);
			}
			throw new UserStoreException("Authentication Failure", e);
		} finally {
			DatabaseUtil.closeAllConnections(dbConnection, rs, prepStmt);
		}
		if (log.isDebugEnabled()) {
			log.debug("UserName " + userName + " login attempt. Login success: " + isAuthed);
		}
		return authenticationResult;
	}

	@Override
	protected String doGetUserIDFromUserNameWithID(String userName) throws UserStoreException {

		if (userName == null) {
			throw new IllegalArgumentException("userName cannot be null.");
		}

		Connection dbConnection = null;
		String sqlStmt;
		PreparedStatement prepStmt = null;
		ResultSet rs = null;
		String userID = null;
		try {
			dbConnection = getDBConnection();

			sqlStmt = "SELECT UM_USER_ID FROM UM_USER WHERE UM_USER_NAME=?";
			prepStmt = dbConnection.prepareStatement(sqlStmt);
			prepStmt.setString(1, userName);

			rs = prepStmt.executeQuery();
			while (rs.next()) {
				userID = rs.getString(1);
			}
		} catch (SQLException e) {
			String msg = "Database error occurred while retrieving userID for a UserName : " + userName;
			if (log.isDebugEnabled()) {
				log.debug(msg, e);
			}
			throw new UserStoreException(msg, e);
		} finally {
			DatabaseUtil.closeAllConnections(dbConnection, rs, prepStmt);
		}

		return userID;
	}

	@Override
	public String doGetUserNameFromUserIDWithID(String userID) throws UserStoreException {

		if (userID == null) {
			throw new IllegalArgumentException("userID cannot be null.");
		}

		Connection dbConnection = null;
		String sqlStmt;
		PreparedStatement prepStmt = null;
		ResultSet rs = null;
		String userName = null;
		try {
			dbConnection = getDBConnection();
			sqlStmt = "SELECT UM_USER_NAME FROM UM_USER WHERE UM_USER_ID=?";

			prepStmt = dbConnection.prepareStatement(sqlStmt);
			prepStmt.setString(1, userID);

			rs = prepStmt.executeQuery();
			while (rs.next()) {
				userName = rs.getString(1);
			}
		} catch (SQLException e) {
			String msg = "Database error occurred while retrieving userName for a userID : " + userID;
			if (log.isDebugEnabled()) {
				log.debug(msg, e);
			}
			throw new UserStoreException(msg, e);
		} finally {
			DatabaseUtil.closeAllConnections(dbConnection, rs, prepStmt);
		}

		return userName;
	}

	@Override
	protected String doGetUserNameFromUserID(String userID) throws UserStoreException {

		if (isUniqueUserIdEnabled()) {
			return doGetUserNameFromUserIDWithID(userID);
		}

		UserUniqueIDManger userUniqueIDManger = new UserUniqueIDManger();
		User user = userUniqueIDManger.getUser(userID, this);
		return user.getUsername();

	}

	@Override
	protected List<String> doGetInternalRoleListOfUserWithID(String userID, String filter) throws UserStoreException {

		String username = doGetUserNameFromUserID(userID);
		if (StringUtils.isEmpty(username)) {
			throw new UserStoreException("No user found with UserID: " + userID);
		}
		return Arrays.asList(hybridRoleManager.getHybridRoleListOfUser(username, filter));
	}

	@Override
	public Map<String, String> getUserPropertyValuesWithID(String userID, String[] propertyNames, String profileName)
			throws UserStoreException {

		// Example code:
		Map<String, String> userProperties = new HashMap<>();

		try (Connection connection = this.getDBConnection()) {
			// Perform necessary database operations to retrieve the user properties
			// Use the connection object to execute SQL queries or any other operations to
			// retrieve the user properties

		List<String> allPropertyNames = new ArrayList<>(Arrays.asList(propertyNames));
			if ((allPropertyNames.get(0).equals("smsOTPDisabled")) || (allPropertyNames.get(0).equals("accountLock"))){
				userProperties.put("smsOTPDisabled", "0");
				userProperties.put("accountLock", "0");
			}

			else {
			StringBuilder queryBuilder = new StringBuilder("SELECT ");
			for (int i = 0; i < allPropertyNames.size(); i++) {
					queryBuilder.append(allPropertyNames.get(i));
					if (i < allPropertyNames.size() - 1) {
						queryBuilder.append(", ");
				}
			}
			queryBuilder.append(" FROM UM_USER WHERE UM_USER_ID=?");
			String sqlQuery = queryBuilder.toString();

			// Example code:
			PreparedStatement statement = connection.prepareStatement(sqlQuery);
			statement.setString(1, userID);
			ResultSet resultSet = statement.executeQuery();
			String propertyValue = null;
			if (resultSet.next()) {
				for (String propertyName : allPropertyNames) {
					propertyValue = resultSet.getString(propertyName);
					userProperties.put(propertyName, propertyValue);		
				}
			}
			}
			
		} catch (SQLException e) {
			throw new UserStoreException("Error occurred while retrieving user properties for ID: " + userID, e);
		}
		return userProperties;
	}

	@Override
	protected void doSetUserAttributesWithID(String userId, Map<String, String> processedClaimAttributes,
			String profileName) throws UserStoreException {

		Connection dbConnection = null;

		try {
			Set<String> receivedProperties = processedClaimAttributes.keySet();
			Map<String, String> alreadyAvailableProperties = getUserPropertyValuesWithID(userId,
					receivedProperties.toArray(new String[0]), profileName);

			dbConnection = getDBConnection();
			
			addPropertiesWithID(dbConnection, userId,
					filterNewlyAddedProperties(processedClaimAttributes, alreadyAvailableProperties), profileName);
			updateProperties(dbConnection, userId,
					filterUpdatedProperties(processedClaimAttributes, receivedProperties, alreadyAvailableProperties),
					profileName);
			dbConnection.commit();
		} catch (SQLException e) {
			DatabaseUtil.rollBack(dbConnection);
			String msg = "Database error occurred while setting user claim values for user : " + userId;

			if (log.isDebugEnabled()) {
				log.debug(msg, e);
			}

			throw new UserStoreException(msg, e);
		} finally {
			DatabaseUtil.closeAllConnections(dbConnection);
		}
	}

	private void addPropertiesWithID(Connection dbConnection, String userID, Map<String, String> properties,
			String profileName) throws UserStoreException {

		String type;
		try {
			type = DatabaseCreator.getDatabaseType(dbConnection);
		} catch (Exception e) {
			String msg = "Error occurred while adding user properties for user : " + userID;
			if (log.isDebugEnabled()) {
				log.debug(msg, e);
			}
			throw new UserStoreException(msg, e);
		}

		String sqlStmt = realmConfig.getUserStoreProperty(JDBCRealmConstants.ADD_USER_PROPERTY_WITH_ID + "-" + type);
		if (sqlStmt == null) {
			sqlStmt = realmConfig.getUserStoreProperty(JDBCRealmConstants.ADD_USER_PROPERTY_WITH_ID);
		}
		if (sqlStmt == null) {
			throw new UserStoreException("The sql statement for add user property sql is null");
		}

		PreparedStatement prepStmt = null;
		boolean localConnection = false;

		try {
			if (dbConnection == null) {
				localConnection = true;
				dbConnection = getDBConnection();
			}
			prepStmt = dbConnection.prepareStatement(sqlStmt);

			Map<String, String> userAttributes = new HashMap<>();
			for (Map.Entry<String, String> entry : properties.entrySet()) {
				String attributeName = entry.getKey();
				String attributeValue = entry.getValue();
				userAttributes.put(attributeName, attributeValue);
			}

			for (Map.Entry<String, String> entry : userAttributes.entrySet()) {
				String propertyName = entry.getKey();
				String propertyValue = entry.getValue();
				if (sqlStmt.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
					if (UserCoreConstants.OPENEDGE_TYPE.equals(type)) {
						batchUpdateStringValuesToDatabase(prepStmt, propertyName, propertyValue, profileName, tenantId,
								userID, tenantId);
					} else {
						batchUpdateStringValuesToDatabase(prepStmt, userID, tenantId, propertyName, propertyValue,
								profileName, tenantId);
					}
				} else {
					batchUpdateStringValuesToDatabase(prepStmt, userID, propertyName, propertyValue, profileName);
				}
			}

			int[] counts = prepStmt.executeBatch();
			if (log.isDebugEnabled()) {
				int totalUpdated = 0;
				if (counts != null) {
					for (int i : counts) {
						totalUpdated += i;
					}
				}

				if (totalUpdated == 0) {
					log.debug("No rows were updated");
				}
				log.debug("Executed query is " + sqlStmt + " and number of updated rows :: " + totalUpdated);
			}

			if (localConnection) {
				dbConnection.commit();
			}
		} catch (SQLException e) {
			DatabaseUtil.rollBack(dbConnection);
			String msg = "Error occurred while updating string values to database.";
			if (log.isDebugEnabled()) {
				log.debug(msg, e);
			}
			throw new UserStoreException(msg, e);
		} finally {
			if (localConnection) {
				DatabaseUtil.closeAllConnections(dbConnection);
			}
			DatabaseUtil.closeAllConnections(null, prepStmt);
		}
	}

	private void batchUpdateStringValuesToDatabase(PreparedStatement prepStmt, Object... params)
			throws UserStoreException {

		try {
			if (params != null && params.length > 0) {
				for (int i = 0; i < params.length; i++) {
					Object param = params[i];
					if (param == null) {
						throw new UserStoreException("Invalid data provided");
					} else if (param instanceof String) {
						prepStmt.setString(i + 1, (String) param);
					} else if (param instanceof Integer) {
						prepStmt.setInt(i + 1, (Integer) param);
					} else if (param instanceof Date) {
						prepStmt.setTimestamp(i + 1, new Timestamp(System.currentTimeMillis()));
					} else if (param instanceof Boolean) {
						prepStmt.setBoolean(i + 1, (Boolean) param);
					}
				}
			}
			prepStmt.addBatch();
		} catch (SQLException e) {
			String msg = "Error occurred while updating property values to database.";
			if (log.isDebugEnabled()) {
				log.debug(msg, e);
			}
			throw new UserStoreException(msg, e);
		}
	}

	private void updateProperties(Connection dbConnection, String userID, Map<String, String> properties,
			String profileName) throws UserStoreException {

		String type;
		try {
			type = DatabaseCreator.getDatabaseType(dbConnection);
		} catch (Exception e) {
			String msg = "Error occurred while updating user properties for user : " + userID;
			if (log.isDebugEnabled()) {
				log.debug(msg, e);
			}
			throw new UserStoreException(msg, e);
		}

		String sqlStmt = realmConfig.getUserStoreProperty(JDBCRealmConstants.UPDATE_USER_PROPERTY_WITH_ID + "-" + type);
		if (sqlStmt == null) {
			sqlStmt = realmConfig.getUserStoreProperty(JDBCRealmConstants.UPDATE_USER_PROPERTY_WITH_ID);
		}
		if (sqlStmt == null) {
			throw new UserStoreException("The sql statement for update user property sql is null.");
		}

		PreparedStatement prepStmt = null;
		boolean localConnection = false;

		try {
			if (dbConnection == null) {
				localConnection = true;
				dbConnection = getDBConnection();
			}
			prepStmt = dbConnection.prepareStatement(sqlStmt);

			for (Map.Entry<String, String> entry : properties.entrySet()) {
				String propertyName = entry.getKey();
				String propertyValue = entry.getValue();
				if (sqlStmt.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
					if (UserCoreConstants.OPENEDGE_TYPE.equals(type)) {
						batchUpdateStringValuesToDatabase(prepStmt, propertyName, propertyValue, profileName, tenantId,
								userID, tenantId);
					} else {
						batchUpdateStringValuesToDatabase(prepStmt, propertyValue, userID, tenantId, propertyName,
								profileName, tenantId);
					}
				} else {
					batchUpdateStringValuesToDatabase(prepStmt, propertyValue, userID, propertyName, profileName);
				}
			}

			int[] counts = prepStmt.executeBatch();
			if (log.isDebugEnabled()) {
				int totalUpdated = 0;
				if (counts != null) {
					for (int i : counts) {
						totalUpdated += i;
					}
				}

				if (totalUpdated == 0) {
					log.debug("No rows were updated");
				}
				log.debug("Executed query is " + sqlStmt + " and number of updated rows :: " + totalUpdated);
			}

			if (localConnection) {
				dbConnection.commit();
			}
		} catch (SQLException e) {
			DatabaseUtil.rollBack(dbConnection);
			String msg = "Error occurred while updating string values to database.";
			if (log.isDebugEnabled()) {
				log.debug(msg, e);
			}
			throw new UserStoreException(msg, e);
		} finally {
			if (localConnection) {
				DatabaseUtil.closeAllConnections(dbConnection);
			}
			DatabaseUtil.closeAllConnections(null, prepStmt);
		}
	}
}
