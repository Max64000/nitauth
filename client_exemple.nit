import nitcorn::restful
import authtoken
import nitcorn

class Authentification
super RestfulAction

	redef fun answer(request, turi)
	do
		print "error"
		return super
	end

	#LOGIN 
	#http://localhost:8080/login?login=test2&password=test3
	fun login(login, password : String): HttpResponse
	is restful do
		var resp = new HttpResponse(200)

		var db = new Sqlite3DB.open("auth.db")
		var result = db.login(login,login,password)
		db.close

		resp.body = "{result}"

		return resp
	end

	#SIGNUP
	#http://localhost:8080/signup?email=test1&username=test2&password=test3
	fun signup(email,username,password : String): HttpResponse
	is restful do
		var resp = new HttpResponse(200)

		var db = new Sqlite3DB.open("auth.db")
		var result = db.add_user_account(email,username,password)
		db.close

		resp.body = "{result}"

		return resp
	end

	#AUTHENTIFICATION TOKEN
	#localhost:8080/authtoken?token=96fb642fd85d5ef5591c374ff12aadc4
	fun authtoken(token : String): HttpResponse
	is restful do
		var resp = new HttpResponse(200)

		var db = new Sqlite3DB.open("auth.db")
		var result = db.check_token(token)
		db.close

		resp.body = "{result}"

		return resp
	end

	#LOGOUT TOKEN
	fun logout(token : String): HttpResponse
	is restful do
		var resp = new HttpResponse(200)

		var db = new Sqlite3DB.open("auth.db")
		var result = db.logout(token)
		db.close

		resp.body = "{result}"

		return resp
	end

	#CHANGE PASSWORD WITH OLDPASSWORD AND NEWPASSWORD
	fun changepassword(idUser, oldPassword,newPassword : String): HttpResponse
	is restful do
		var resp = new HttpResponse(200)

		var db = new Sqlite3DB.open("auth.db")
		var result = db.changepassword(idUser, oldPassword,newPassword)
		db.close

		resp.body = "{result}"

		return resp
	end


	#CHANGE PASSWORD REQUEST
	#http://localhost:8080/requestchangepassword?emailorusername=maxime.vergne@viacesi.fr
	fun requestchangepassword(emailorusername : String) : HttpResponse
	is restful do
		var resp = new HttpResponse(200)

		var iduser = "false"

		var db = new Sqlite3DB.open("auth.db")
		iduser = db.getIdUserByEmailOrUsername(emailorusername)
		if iduser != "false" 
		then
			#génération d'un token de changement de motdepasse
			var tokencp = db.change_password_genere(iduser)
			resp.body = "okay !"
			
			#récupération email user
			var usermail = db.getEmailUser(iduser)

			var mymail = new MyMail(usermail,"Changement de votre mot de passe","Pour changer votre mot de passe lien : http://localhost:8080/pagechangepassword?tokencp={tokencp}")
			db.sendMail(mymail)
			
		end
		
		db.close

		return resp
	end


	#PAGE CHANGE PASSWORD WITH TOKEN CHANGE PASSWORD
	fun pagechangepassword(tokencp : String) : HttpResponse
	is restful do

		var db = new Sqlite3DB.open("auth.db")

		var response = new HttpResponse(200)

		if db.check_token_cp(tokencp) == true then
				response.body = """
			<div class="container">
				<div class="col-md-12 text-center">
					<div class="row">
						<form class="navbar-form" role="form" action="changepasswordpost?tokencp={{{tokencp}}}" method="POST">
							<div class="col-md-4">
										<label>Votre nouveau mot de passe :</label>
							</div>
							<div class="col-md-8">
								<input type="password" class="form-control" name="password" id="password" style="width:150px;"required>
							</div>
							<div class="col-md-4">
										<label>Confirmation du mot de passe :</label>
							</div>
							<div class="col-md-8">
								<input type="password" class="form-control" name="passwordconfirmation" id="passwordconfirmation" style="width:150px;"required>
							</div>
							<br>
							<div class="col-md-12">
								<button type="submit" class="btn btn-default">Valider</button>
							</div>
						</form>
					</div>
				</div>
			</div>
			"""
		else
			response.body = "erreur token"
		end

		db.close

		return response
	end
	

	#CHANGE PASSWORD POST
	fun changepasswordpost(tokencp,password,passwordconfirmation : String) : HttpResponse
	is restful do
		var resp = new HttpResponse(200)
		var db = new Sqlite3DB.open("auth.db")

		
		if password != passwordconfirmation then
			resp.body = "erreur confirmation du mot de passe"
		else
			if db.check_token_cp(tokencp) == true then
				var result = db.change_password(tokencp,password)
				resp.body = "changement du mot de passe okay"
			else
				resp.body = "erreur token"
			end
		end
		
		db.close
		

		return resp
	end

end

var vh = new VirtualHost("localhost:8080")

# Serve everything with our restful action
vh.routes.add new Route(null, new Authentification)

# Avoid executing when running tests
if "NIT_TESTING".environ == "true" then exit 0

var factory = new HttpFactory.and_libevent
factory.config.virtual_hosts.add vh
factory.run
