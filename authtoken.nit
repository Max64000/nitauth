module authtoken
import sqlite3
import md5
import sha1

redef class Sqlite3DB
	#attribut salt
	var salt = "secretsaltmontreal1a2z3e4r5t6y7u8i9o"
	#initialisation création des tables
	init
	do
		create_tables_users
		create_tables_token
		create_table_change_password
	end

	#Création de la table users
	private fun create_tables_users
	do
		assert create_table("IF NOT EXISTS user (id_user INTEGER PRIMARY KEY AUTOINCREMENT, email_user TEXT, pseudonyme_user TEXT, password_user TEXT)") else
			print error or else "?"
		end
	end

	#Création de la table token des users
	private fun create_tables_token
	do
		assert create_table("IF NOT EXISTS user_token (id_user INTEGER, token_user TEXT)") else
			print error or else "?"
		end
	end

	#Création de la table id
	private fun create_table_change_password
	do
		assert create_table("IF NOT EXISTS user_change_password (id_user INTEGER, id_change_password TEXT)") else
			print error or else "?"
		end
	end


	#Vérification si un compte existe pour l'enregistrement (return true si le compte exist sinon false)
	private fun check_account_exist(email,pseudonyme : String) : Bool
	do
		var result:Bool = false
		var stmt = select("email_user, pseudonyme_user FROM user WHERE email_user={email.to_sql_string} OR pseudonyme_user={pseudonyme.to_sql_string}")
		
		assert stmt != null else print error or else "?"

		for row in stmt do
			if row[0].to_s == email or row[1].to_s == pseudonyme then
				result = true
			end
		end
		return result
	end

	#Génération d'un token (return string du token)
	private fun createToken: String
	do
		var token1 = 123456.rand.to_s
		var token2 = 123456.rand.to_s

		var token = token1 + token2
		token = token.md5
		return token
	end

	#Enregistrement d'un compte retourne boolean (return true si okay)
	fun add_user_account(email,pseudonyme,password : String) : Bool
	do
		#password sécurité
		password = password + salt
		password = password.sha1_hexdigest
		#compte exist
		if check_account_exist(email,pseudonyme) == false then
			assert insert("INTO user(email_user, pseudonyme_user, password_user) VALUES ({email.to_sql_string}, {pseudonyme.to_sql_string}, {password.to_sql_string})") else
				print error or else "?"
			end
			return true
		end

		return false
	end

	#Login d'un compte return token ou null (return token user sinon false en string)
	fun login(email,pseudonyme,password :String) : String
	do
		var id_user = null
		var result = false

		password = password + salt
		password = password.sha1_hexdigest

		var stmt = select("id_user, email_user, pseudonyme_user, password_user FROM user WHERE (email_user={email.to_sql_string} AND password_user={password.to_sql_string}) OR (pseudonyme_user={pseudonyme.to_sql_string} AND password_user={password.to_sql_string})")
		assert stmt != null else print error or else "?"
		for row in stmt do
			if row[1].to_s == email and row[3].to_s == password then
				result = true
				id_user = row[0].to_s 
			else if row[2].to_s == pseudonyme and row[3].to_s == password then
				result = true
				id_user = row[0].to_s 
			end
		end

		if result == true then
			assert id_user != null else return "false"

			var token = createToken

			assert insert("INTO user_token(id_user, token_user) VALUES ({id_user}, {token.to_sql_string})") else
				print error or else "?"
			end
			
			
			return token
		end
		

		return "false"
	end

	#obtenir email user par iduser (return email de l'utilisateur en string)
	fun getEmailUser(iduser: String) : String
	do	
		var stmt = select("email_user FROM user WHERE id_user = {iduser.to_sql_string}")
		assert stmt != null else print error or else "?"
		for row in stmt do
			return row[0].to_s
		end
		return ""
	end


	#Logout retourne un boolean si token = null (return true si déco de l'utilisateur et suppresion du token user)
	fun logout(token : String) : Bool
	do
		var resultExistUser = check_token(token)
		if resultExistUser != "false"
		then
			assert execute("DELETE FROM user_token WHERE token_user = {token.to_sql_string}") else
				print error or else "?"
			end
			return true
		end

		return false
	end
	
	#Check du token retourne iduser ou false (return String si token exist sinon string avec false)
	fun check_token(token : String) : String
	do
		var stmt = select("token_user,id_user FROM user_token WHERE token_user = {token.to_sql_string}")
		
		assert stmt != null else print error or else "?"
		for row in stmt do
			if row[0].to_s == token then
				return row[1].to_s
			end
		end
		return "false"
	end

	#Changement du mot de passe à partir du compte (return true si changement de mot de passe)
	fun changepassword(idUser, oldPassword, newPassword : String) : Bool
	do
		var validinfo:Bool = false
		oldPassword = oldPassword + salt
		oldPassword = oldPassword.sha1_hexdigest

		var stmt = select("id_user, password_user FROM user WHERE id_user={idUser}")
		
		assert stmt != null else print error or else "?"
		for row in stmt do
			if row[0].to_s == idUser and row[1].to_s == oldPassword then
				validinfo = true
 			end
		end

		if validinfo == true then
			newPassword = newPassword + salt
			newPassword = newPassword.sha1_hexdigest

			assert execute("UPDATE user SET password_user={newPassword.to_sql_string} WHERE id_user = {idUser.to_sql_string}") else
				print error or else "?"
			end
			return true 
		else
			return false
		end

	end

	#génération d'un token change password pour le changement de mot de passe (return string token change password)
	fun change_password_genere(iduser: String) : String
	do
		var token = createToken
		assert insert("INTO user_change_password(id_user, id_change_password) VALUES ({iduser}, {token.to_sql_string})") else
			print error or else "?"
		end

		return token
	end

	#changement du mot de passe avec tokencp généré (return true : changement de mot de passe okay)
	fun change_password(token, password : String) : Bool
	do
		var stmt = select("id_user, id_change_password FROM user_change_password WHERE id_change_password={token.to_sql_string}")
		

		assert stmt != null else print error or else "?"

		for row in stmt do
			if row[1].to_s == token then
			
				var iduser = row[0].to_s
				password = password + salt
				password = password.sha1_hexdigest

				assert execute("UPDATE user SET password_user={password.to_sql_string} WHERE id_user = {iduser.to_sql_string}") else
					print error or else "?"
				end

				assert execute("DELETE FROM user_change_password WHERE id_change_password = {token.to_sql_string}") else
					print error or else "?"
				end

				return true

			end
		end

		return false
	end

	#check si tokencp exist (return true = token change password exist)
	fun check_token_cp(tokencp: String) : Bool
	do
		var stmt = select("id_change_password FROM user_change_password ")

		assert stmt != null else print error or else "?"

		for row in stmt do
			if tokencp == row[0].to_s then
				return true
			end
		end

		return false
	end

	#Liste users (return list Users)
	fun liste_users : Array[Users]
	do
		var stmt = select("id_user, email_user, pseudonyme_user FROM user")
		assert stmt != null else print error or else "?"
		
		var users = new Array[Users]

		for row in stmt do users.add new Users(row[0].to_s, row[1].to_s, row[2].to_s)
		
		return users

	end


	
end

class Users
	var iduser: String
	var email : String
	var pseudonyme : String
end
