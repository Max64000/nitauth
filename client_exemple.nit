import nitcorn::restful
import authtoken
import core
import sendmail
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

	#Enregistrement
	#http://localhost:8080/signup?email=test1&pseudonyme=test2&password=test3
	fun signup(email,pseudonyme,password : String): HttpResponse
	is restful do
		var resp = new HttpResponse(200)

		var db = new Sqlite3DB.open("auth.db")
		var result = db.add_user_account(email,pseudonyme,password)
		db.close

		resp.body = "{result}"

		return resp
	end

	#Vérification du token
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

	#Deconnecter le token
	fun logout(token : String): HttpResponse
	is restful do
		var resp = new HttpResponse(200)

		var db = new Sqlite3DB.open("auth.db")
		var result = db.logout(token)
		db.close

		resp.body = "{result}"

		return resp
	end

	#changement mot de passe en ayant l'ancien
	fun changepassword(idUser, oldPassword,newPassword : String): HttpResponse
	is restful do
		var resp = new HttpResponse(200)

		var db = new Sqlite3DB.open("auth.db")
		var result = db.changepassword(idUser, oldPassword,newPassword)
		db.close

		resp.body = "{result}"

		return resp
	end



	#http://localhost:8080/requestchangepassword?tokenuser=96fb642fd85d5ef5591c374ff12aadc4
	#demander un changement de mot si mot de passe oublié (envoir mail avec lien)
	fun requestchangepassword(tokenuser : String) : HttpResponse
	is restful do
		var resp = new HttpResponse(200)

		var iduser = "false"

		var db = new Sqlite3DB.open("auth.db")
		iduser = db.check_token(tokenuser)
		if iduser != "false" 
		then
			#génération d'un token de changement de motdepasse
			var resulttoken = db.change_password_genere(iduser)
			resp.body = "okay !"
			
			#récupération email user
			var usermail = db.getEmailUser(iduser)

			if sendmail_is_available then
		    var mail = new Mail("{usermail}", "Changement de votre mot de passe ", "Pour changer votre mot de passe lien : http://localhost:8080/pagechangepassword?tokencp={resulttoken}")
		    	mail.to.add "{usermail}"
		    	mail.send
			else print "please install sendmail"
		end
		
		db.close

		return resp
	end

	#page de changement de mot de passe (lien email)
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
	

	#changement du password post
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
