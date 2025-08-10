import uploadImageClodinary from '../utils/uploadImageToCloudinary.js'

const uploadImageController = async(request,response)=>{
    try {
        const file = request.file
        console.log("file",file)
        const uploadImage = await uploadImageClodinary(file)

        return response.json({
            message : "Image Uploaded Successfully",
            data : uploadImage,
            success : true,
            error : false
        })
    } catch (error) {
        console.log("error in upload image controller",error)
        return response.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
    }
}

export default uploadImageController