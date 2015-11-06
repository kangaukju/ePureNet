/*
 * ip_objector.h
 *
 *  Created on: 2009. 8. 31.
 *      Author: kinow
 */

#ifndef IP_OBJECTOR_H_
#define IP_OBJECTOR_H_

#include "base_objector.h"

class ip_objector : public base_objector<SET_NUM_T>{
public:

	virtual bool find(const void * value){
		SET_NUM_T * num = (SET_NUM_T *) value;
		set<T>::iterator it = m_objector_set.find(num);
		if(it == m_objector_set.end())			return false;
		else									return true;
	}


	virtual bool load(mysql_loader *sql_loader, string db_name, string url_list_table=""){

		sql::PreparedStatement	*prep_stmt 	= NULL;
		sql::Connection			*connection = NULL;
		sql::ResultSet			*result 	= NULL;

		try{
			connection = sql_loader->get_connect();
			if(connection != NULL){

				// select database
				connection->setSchema(db_name);

				/*
				 * 쿼리 넣기
				 */
				string query = 	"select distinct A.i_l_name " +
								//from table
								"from ip_list as A, ip_obj_map as B, ip_object as C, ip_obj_impl as D, objects as E "+
								//where
								"where "+
								"E.enable = 1 and "+
								"E.o_num = D.o_num and "+
								"C.i_o_num = D.i_o_num and "+
								"D.i_o_num = B.i_o_num and "+
								"B.i_l_num = A.i_l_num and "+
								"B.i_num = A.i_num";

				prep_stmt 	= connection->prepareStatement(query);
				result 		= prep_stmt->executeQuery();

				while( result->next() ){
					const char * ip_list = result->getString(1).c_str();
					SET_NUM_T ip;
					inet_pton(AF_INET, ip_list, &ip);

					//insert
					m_objector_set.insert(ip);
				}
			}

			delete result;
			delete prep_stmt;
			sql_loader->close();

			/*
			 * 데이터베이스에서 다운로드
			 * 참고 자료 http://blog.ulf-wendel.de/?p=229
			 * http://forge.mysql.com/wiki/Connector_C%2B%2B
			 */

		}catch(sql::SQLException &e){
			cout << "# ERR: SQLException in " << __FILE__;
			cout << "(" << __FUNCTION__ << ") on line " << __LINE__ << endl;

			cout << "# ERR: " << e.what();
			cout << " (MySQL error code: " << e.getErrorCode();
			cout << ", SQLState: " << e.getSQLState() << " )" << endl;

			delete result;
			delete prep_stmt;
			sql_loader->close();
			return false;
		}
		return true;
	}
};

#endif /* IP_OBJECTOR_H_ */
